# Setup
`cp .env.example .env` and edit the values. The account you specify in that file will be the miner of the clique network and will have ETH allocated in the genesis block.

If you make changes to the genesis file, then you may have to delete the existing change via `docker compose down --volumes` - this will delete any volumes associated with this setup.
Use `docker compose up` to start the chain.
