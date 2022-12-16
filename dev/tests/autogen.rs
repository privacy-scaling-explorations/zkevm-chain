#![cfg(feature = "autogen")]

use eth_types::Bytes;
use zkevm_dev::bytecode::*;
use zkevm_dev::genesis::patch_genesis_l2;

#[test]
fn autogen_genesis() {
    patch_genesis_l2(
        "worst-case smod",
        0x100001,
        Bytes::from(gen_bytecode_smod(300_000)),
    );

    patch_genesis_l2(
        "worst-case mload",
        0x100002,
        Bytes::from(gen_bytecode_mload(300_000)),
    );

    patch_genesis_l2(
        "worst-case keccak_0_32",
        0x100003,
        Bytes::from(gen_bytecode_keccak_0_32(300_000)),
    );
}
