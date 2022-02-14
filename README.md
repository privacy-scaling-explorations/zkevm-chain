## Structure

`coordinator/`: coordinator daemon
`docker/`: dockerfiles for various purposes
`scripts/`: helpful scripts
`testnet/`: contains files associated with the zkevm testnet

## Setup
`cp .env.example .env` and edit the values. The account you specify in that file will be the miner of the clique network and will have ETH allocated in the genesis block.

If you make changes to the genesis file, then you have to delete the existing chain via `docker compose down --volumes` - this will delete any volumes associated with this setup.
Use `docker compose up` to start the chain.

You can use `./scripts/dev.sh` to start a local dev environment without the coordinator-service that drops you into a shell. Useful if you want to work on the `coordinator/` daemon.
