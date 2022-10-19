#!/usr/bin/env node

import fs from 'fs';

function pad (n, v) {
  return v.toString(16).padStart(n, '0');
}

function getCode (name) {
  const json = JSON.parse(fs.readFileSync(`./build/contracts/${name}.json`));

  return '0x' + json['bin-runtime'];
}

const L1_CONTRACTS = {
  '936a70c0b28532aa22240dce21f89a8399d6ac60': 'ZkEvmL1Bridge',
  '936a70c0b28532aa22240dce21f89a8399d6ac61': 'L1OptimismBridge',
};
const baseAddress = BigInt('0x1111111111111111111111111111111111111111');
const path = './build/plonk-verifier';
for (const file of fs.readdirSync(path)) {
  const json = JSON.parse(fs.readFileSync(`${path}/${file}`));
  let addr = pad(40, BigInt(json.config.block_gas_limit + json.instance.length));
  console.log({file, addr});
  L1_CONTRACTS[addr] = { name: file, code: json.runtime_code };
}

const L2_CONTRACTS = {
  '0000000000000000000000000000000000010000': 'ZkEvmL2MessageDeliverer',
  '0000000000000000000000000000000000020000': 'ZkEvmL2MessageDispatcher',
  '4200000000000000000000000000000000000007': 'L2OptimisimBridge',
};
const L1_TEMPLATE_PATH = 'docker/geth/templates/l1-testnet.json';
const L2_TEMPLATE_PATH = 'docker/geth/templates/l2-testnet.json';

const PROXY_CODE = getCode('Proxy');
const PROXY_SLOT = pad(64, BigInt.asUintN(256, '-1'));

const OBJS = [
  [L1_TEMPLATE_PATH, L1_CONTRACTS],
  [L2_TEMPLATE_PATH, L2_CONTRACTS],
];

for (const [path, contracts] of OBJS) {
  const genesis = JSON.parse(fs.readFileSync(path));

  for (const addr in contracts) {
    let value = contracts[addr];
    if (typeof value === 'string') {
      const code = getCode(value);
      const proxy = genesis.alloc[addr] || { balance: '0' };
      proxy.comment = 'Proxy:' + value;
      proxy.code = PROXY_CODE;
      proxy.storage = proxy.storage || {};
      const implAddr = pad(40, BigInt.asUintN(160, BigInt('0x' + addr) + 0xcbaf2257000313ba2574n));
      proxy.storage[PROXY_SLOT] = implAddr;
      genesis.alloc[addr] = proxy;

      genesis.alloc[implAddr] = {
        comment: value,
        balance: '0',
        code
      };
    } else {
      const code = value.code;
      const name = value.name;
      const account = genesis.alloc[addr] || { balance: '0' };
      account.comment = name;
      account.code = code;
      genesis.alloc[addr] = account;
    }
  }

  fs.writeFileSync(path, JSON.stringify(genesis, null, 2));
}
