export default {
  artifactsPath: 'build/contracts',
  proxyPort: 8545,
  rpcUrl: process.env.RPC,
  fuzzyMatchFactor: 0.8,
  ignore: /(mocks|tests|interfaces)\/.*\.sol/,
}
