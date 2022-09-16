use crate::ProverParams;
use halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::transcript::TranscriptReadBuffer;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{self, Circuit, ConstraintSystem},
};
use itertools::Itertools;
use plonk_verifier::loader::halo2::halo2_wrong_ecc::{
    integer::rns::Rns,
    maingate::{
        MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig, RangeInstructions,
        RegionCtx,
    },
    EccConfig,
};
use plonk_verifier::loader::halo2::halo2_wrong_transcript::NativeRepresentation;
use plonk_verifier::{
    loader,
    pcs::{
        kzg::{Accumulator, PreAccumulator},
        PreAccumulator as _,
    },
    system,
    util::{
        arithmetic::{fe_to_limbs, FieldExt},
        transcript::Transcript,
    },
    Protocol,
};
use plonk_verifier::{
    pcs::kzg::{Gwc19, KzgOnSameCurve},
    verifier::{self, PlonkVerifier},
};
use std::iter;
use std::rc::Rc;

const LIMBS: usize = 4;
const BITS: usize = 68;
pub type Plonk = verifier::Plonk<KzgOnSameCurve<Bn256, Gwc19<Bn256>, LIMBS, BITS>>;

const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 57;

type BaseFieldEccChip = loader::halo2::halo2_wrong_ecc::BaseFieldEccChip<G1Affine, LIMBS, BITS>;
type Halo2Loader<'a> = loader::halo2::Halo2Loader<'a, G1Affine, Fr, BaseFieldEccChip>;
pub type PoseidonTranscript<L, S, B> = system::halo2::transcript::halo2::PoseidonTranscript<
    G1Affine,
    Fr,
    NativeRepresentation,
    L,
    S,
    B,
    LIMBS,
    BITS,
    T,
    RATE,
    R_F,
    R_P,
>;

pub struct Snark {
    protocol: Protocol<G1Affine>,
    instances: Vec<Vec<Fr>>,
    proof: Vec<u8>,
}

impl Snark {
    pub fn new(protocol: Protocol<G1Affine>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) -> Self {
        Self {
            protocol,
            instances,
            proof,
        }
    }
}

impl From<Snark> for SnarkWitness {
    fn from(snark: Snark) -> Self {
        Self {
            protocol: snark.protocol,
            instances: snark
                .instances
                .into_iter()
                .map(|instances| instances.into_iter().map(Value::known).collect_vec())
                .collect(),
            proof: Value::known(snark.proof),
        }
    }
}

#[derive(Clone)]
pub struct SnarkWitness {
    protocol: Protocol<G1Affine>,
    instances: Vec<Vec<Value<Fr>>>,
    proof: Value<Vec<u8>>,
}

impl SnarkWitness {
    fn without_witnesses(&self) -> Self {
        SnarkWitness {
            protocol: self.protocol.clone(),
            instances: self
                .instances
                .iter()
                .map(|instances| vec![Value::unknown(); instances.len()])
                .collect(),
            proof: Value::unknown(),
        }
    }
}

pub fn accumulate<'a>(
    g1: &G1Affine,
    loader: &Rc<Halo2Loader<'a>>,
    snark: &SnarkWitness,
    curr_accumulator: Option<PreAccumulator<G1Affine, Rc<Halo2Loader<'a>>>>,
) -> PreAccumulator<G1Affine, Rc<Halo2Loader<'a>>> {
    let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _, _>::new(
        loader,
        snark.proof.as_ref().map(|proof| proof.as_slice()),
    );
    let instances = snark
        .instances
        .iter()
        .map(|instances| {
            instances
                .iter()
                .map(|instance| loader.assign_scalar(*instance))
                .collect_vec()
        })
        .collect_vec();
    let proof = Plonk::read_proof(&snark.protocol, &instances, &mut transcript).unwrap();
    let mut accumulator = Plonk::succint_verify(g1, &snark.protocol, &instances, &proof).unwrap();
    if let Some(curr_accumulator) = curr_accumulator {
        accumulator += curr_accumulator * transcript.squeeze_challenge();
    }
    accumulator
}

#[derive(Clone)]
pub struct AggregationConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl AggregationConfig {
    pub fn configure<F: FieldExt>(
        meta: &mut ConstraintSystem<F>,
        composition_bits: Vec<usize>,
        overflow_bits: Vec<usize>,
    ) -> Self {
        let main_gate_config = MainGate::<F>::configure(meta);
        let range_config =
            RangeChip::<F>::configure(meta, &main_gate_config, composition_bits, overflow_bits);
        AggregationConfig {
            main_gate_config,
            range_config,
        }
    }

    pub fn main_gate(&self) -> MainGate<Fr> {
        MainGate::new(self.main_gate_config.clone())
    }

    pub fn range_chip(&self) -> RangeChip<Fr> {
        RangeChip::new(self.range_config.clone())
    }

    pub fn ecc_chip(&self) -> BaseFieldEccChip {
        BaseFieldEccChip::new(EccConfig::new(
            self.range_config.clone(),
            self.main_gate_config.clone(),
        ))
    }
}

#[derive(Clone)]
pub struct AggregationCircuit {
    g1: G1Affine,
    snarks: Vec<SnarkWitness>,
    instances: Vec<Fr>,
}

impl AggregationCircuit {
    pub fn new(params: &ProverParams, snarks: impl IntoIterator<Item = Snark>) -> Self {
        let g1 = params.get_g()[0];
        let snarks = snarks.into_iter().collect_vec();

        let accumulator = snarks
            .iter()
            .fold(None, |curr_accumulator, snark| {
                let mut transcript = PoseidonTranscript::init(snark.proof.as_slice());
                let proof =
                    Plonk::read_proof(&snark.protocol, &snark.instances, &mut transcript).unwrap();
                let mut accumulator =
                    Plonk::succint_verify(&g1, &snark.protocol, &snark.instances, &proof).unwrap();
                if let Some(curr_accumulator) = curr_accumulator {
                    accumulator += curr_accumulator * transcript.squeeze_challenge();
                }
                Some(accumulator)
            })
            .unwrap();

        let Accumulator { lhs, rhs } = accumulator.evaluate();
        let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
            .map(fe_to_limbs::<_, _, LIMBS, BITS>)
            .concat();

        Self {
            g1,
            snarks: snarks.into_iter().map_into().collect(),
            instances,
        }
    }

    pub fn accumulator_indices() -> Vec<(usize, usize)> {
        (0..4 * LIMBS).map(|idx| (0, idx)).collect()
    }

    pub fn num_instance() -> Vec<usize> {
        vec![4 * LIMBS]
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instances.clone()]
    }
}

impl Circuit<Fr> for AggregationCircuit {
    type Config = AggregationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            g1: self.g1,
            snarks: self
                .snarks
                .iter()
                .map(SnarkWitness::without_witnesses)
                .collect(),
            instances: Vec::new(),
        }
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
        AggregationConfig::configure(
            meta,
            vec![BITS / LIMBS],
            Rns::<Fq, Fr, LIMBS, BITS>::construct().overflow_lengths(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        let main_gate = config.main_gate();
        let range_chip = config.range_chip();

        range_chip.load_table(&mut layouter)?;

        let (lhs, rhs) = layouter.assign_region(
            || "",
            |region| {
                let ctx = RegionCtx::new(region, 0);

                let ecc_chip = config.ecc_chip();
                let loader = Halo2Loader::new(ecc_chip, ctx);
                let accumulator = self
                    .snarks
                    .iter()
                    .fold(None, |accumulator, snark| {
                        Some(accumulate(&self.g1, &loader, snark, accumulator))
                    })
                    .unwrap();
                let Accumulator { lhs, rhs } = accumulator.evaluate();

                Ok((lhs.into_normalized(), rhs.into_normalized()))
            },
        )?;

        for (limb, row) in iter::empty()
            .chain(lhs.x().limbs())
            .chain(lhs.y().limbs())
            .chain(rhs.x().limbs())
            .chain(rhs.y().limbs())
            .zip(0..)
        {
            main_gate.expose_public(layouter.namespace(|| ""), limb.into(), row)?;
        }

        Ok(())
    }
}
