# Deprecated - zkevm-chain

**Important Notice:** This repository is no longer actively maintained or supported, and contains a vulnerability in the smart contracts.

For some months already we have determined that the scope of our project doesn't involve building an L2 zkRollup.  Our main goals are: build a system to generate zk proofs of correct Ethereum Block processing, and from this create a project where proofs for each L1 block are generated so that light clients can sync with very low resources requirement.  A secondary goal is to offer the Block zk proof system as a library/toolkit for others to build a zkRollup on top of it.  This means we're not actively developing mechanisms related to managing an L2 (decision for making blocks, coordinators, bridging, etc.).  The zkevm-chain repo started with that aim but after our shift in focus it remained as an infrastructure for end-to-end testing of blocks zk proofs and benchmarking.

This repository contains an [**unfixed DoS vulnerability** in the smart contracts code](https://github.com/privacy-scaling-explorations/zkevm-chain/security/advisories/GHSA-6m99-mxg3-pv9h); please be aware of this if you decide use this repository in any way.
