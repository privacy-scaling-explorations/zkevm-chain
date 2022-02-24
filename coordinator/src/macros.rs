/// Wraps a expression inside an async block that timeouts after `a` ms
#[macro_export]
macro_rules! timeout {
    ($a:literal, $b:expr) => {
        async {
            let res =
                tokio::time::timeout(std::time::Duration::from_millis($a), async { $b }).await;

            if let Err(err) = &res {
                log::error!("timeout: {}", err);
            }
            res
        }
        .await
        .unwrap()
    };
}
