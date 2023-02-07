use std::collections::VecDeque;
use std::sync::Arc;

use ethers_core::types::Address;
use ethers_core::types::U256;
use ethers_signers::Signer;

use tokio::spawn;
use tokio::sync::Mutex;

use crate::shared_state::SharedState;

#[derive(Clone)]
pub struct Faucet {
    pub queue: Arc<Mutex<VecDeque<Address>>>,
}

impl Default for Faucet {
    fn default() -> Faucet {
        Faucet {
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

impl Faucet {
    /// Iterates over `queue` and sends ETH with the `shared_state.ro.l1_wallet`.
    /// To avoid replacing transactions or invoking other race conditions,
    /// this function should not be run in parallel with any other `SharedState` tasks.
    /// Only consumes up to `max_items` items from the queue each time.
    pub async fn drain(&self, shared_state: SharedState, max_items: usize) {
        let mut queue = self.queue.lock().await;
        let mut remaining_balance: U256 = shared_state
            .request_l1(
                "eth_getBalance",
                (shared_state.ro.l1_wallet.address(), "latest"),
            )
            .await
            .expect("l1 balance");

        // can be made configurable if needed
        let faucet_amount = U256::from(1000000000000000000u64);
        let min_wallet_balance = U256::from(1000000000000000000u64);

        let mut i = 0;
        for receiver in queue.iter().take(max_items) {
            log::info!("transfer of {} for {:?}", faucet_amount, receiver);

            if remaining_balance < faucet_amount {
                log::warn!(
                    "remaining balance ({}) less than faucet amount ({})",
                    remaining_balance,
                    faucet_amount
                );
                break;
            }
            if remaining_balance - faucet_amount < min_wallet_balance {
                log::warn!("faucet wallet balance is too low ({})", remaining_balance);
                break;
            }

            // spawn task to catch panics
            {
                #[allow(clippy::clone_on_copy)]
                let receiver = receiver.clone();
                let shared_state = shared_state.clone();
                let res = spawn(async move {
                    shared_state
                        .transaction_to_l1(Some(receiver), faucet_amount, vec![])
                        .await
                        .expect("receipt");
                })
                .await;

                if let Err(err) = res {
                    log::error!("drain: {}", err);
                    break;
                }
            }

            remaining_balance -= faucet_amount;
            i += 1;
        }

        // drain all successful transfers
        queue.drain(0..i);
    }
}
