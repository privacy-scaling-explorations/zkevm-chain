#!/usr/bin/env node

import fs from 'fs';

function pad (n, v) {
  return v.toString(16).padStart(n, '0');
}

function getCode (name) {
  for (const id in artifacts) {
    if (id.split(':')[1] === name) {
      return '0x' + artifacts[id]['bin-runtime'];
    }
  }

  throw new Error(`${name} not found`);
}

const artifacts = JSON.parse(fs.readFileSync('./build/contracts/combined.json')).contracts;
const L1_CONTRACTS = {
  '936a70c0b28532aa22240dce21f89a8399d6ac60': 'ZkEvmL1Bridge',
  '936a70c0b28532aa22240dce21f89a8399d6ac61': 'L1OptimismBridge',
};
const baseAddress = BigInt('0x1111111111111111111111111111111111111111');
const path = './build/contracts/plonk-verifier';
if (fs.existsSync(path)) {
  for (const file of fs.readdirSync(path)) {
    const runtime_code = '0x' + fs.readFileSync(`${path}/${file}`);
    const addr = pad(40, BigInt(file.split('-').pop()));
    console.log({file, addr});
    if (L1_CONTRACTS[addr]) {
      throw Error('exists');
    }
    L1_CONTRACTS[addr] = { name: file, code: runtime_code };
  }
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
    let code;
    let name;
    let value = contracts[addr];
    if (typeof value === 'string') {
      code = getCode(value);
      name = value;
    } else {
      code = value.code;
      name = value.name;
    }

    const proxy = genesis.alloc[addr] || { balance: '0' };
    proxy.comment = 'Proxy:' + name;
    proxy.code = PROXY_CODE;
    proxy.storage = proxy.storage || {};
    const implAddr = pad(40, BigInt.asUintN(160, BigInt('0x' + addr) + 0xcbaf2257000313ba2574n));
    proxy.storage[PROXY_SLOT] = implAddr;
    genesis.alloc[addr] = proxy;

    genesis.alloc[implAddr] = {
      comment: name,
      balance: '0',
      code
    };
  }

  fs.writeFileSync(path, JSON.stringify(genesis, null, 2));
}
