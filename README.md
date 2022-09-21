## Structure

|Path|Description|
|-|-|
|`coordinator/`|coordinator daemon|
|`contracts/`|l1/l2 bridge contracts|
|`docker/`|dockerfiles for various purposes|
|`scripts/`|helpful scripts|

## Setup
`cp .env.example .env` and edit the values. The account you specify in that file will be the miner of the clique network and will have ETH allocated in the genesis block.

If you make changes to the genesis file, then you have to delete the existing chain via `docker compose down --volumes` - this will delete any volumes associated with this setup.
Use `DOCKER_BUILDKIT=1 docker compose up` to start the chain.

You can use `./scripts/dev.sh` to start a local dev environment without the coordinator-service that drops you into a shell. Useful if you want to work on the `coordinator/` daemon.

## Developer workflows
###### Testing the coordinator & prover with `cargo test`
Enter the developer service via `./scripts/dev.sh`.
Inside that shell you can use this wrapper script to build & start the `prover_rpcd` in the background and invoke `cargo test -- eth_transfer`:
```
./scripts/test_prover.sh eth_transfer
```
The output of the prover damon will be piped to `PROVER_LOG.txt`.
If you need fixtures for the L2 block with number 1, then use `./scripts/get_block_fixtures.sh $COORDINATOR_L2_RPC_URL 1` to retrieve it for you.

