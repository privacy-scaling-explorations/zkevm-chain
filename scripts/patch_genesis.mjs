#!/usr/bin/env node

import fs from 'fs';

const L1_CONTRACTS = {
  '936a70c0b28532aa22240dce21f89a8399d6ac60': 'ZkEvmL1Bridge.bin-runtime',
  '936a70c0b28532aa22240dce21f89a8399d6ac61': 'L1OptimismBridge.bin-runtime',
  // for tests
  '00000000000000000000000000000000000f0000': 'TestPatricia.bin-runtime',
};
const L2_CONTRACTS = {
  '0000000000000000000000000000000000010000': 'ZkEvmL2MessageDeliverer.bin-runtime',
  '0000000000000000000000000000000000020000': 'ZkEvmL2MessageDispatcher.bin-runtime',
  '4200000000000000000000000000000000000007': 'L2OptimisimBridge.bin-runtime',
};
const L1_TEMPLATE_PATH = './testnet/l1-genesis-template.json';
const L2_TEMPLATE_PATH = './testnet/l2-genesis-template.json';

const OBJS = [
  [L1_TEMPLATE_PATH, L1_CONTRACTS],
  [L2_TEMPLATE_PATH, L2_CONTRACTS],
];

for (const [path, contracts] of OBJS) {
  const genesis = JSON.parse(fs.readFileSync(path));

  for (const addr in contracts) {
    const value = contracts[addr];
    const code = fs.readFileSync('./build/contracts/' + value).toString();
    genesis.alloc[addr].code = '0x' + code;
  }

  fs.writeFileSync(path, JSON.stringify(genesis, null, 2));
}
