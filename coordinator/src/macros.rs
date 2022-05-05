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

/// Returns `None` if env variable `a` is not set or disabled ("", "0" or "false").
/// Otherwise returns `Some(b)`.
#[macro_export]
macro_rules! option_enabled {
    ($a:literal, $b:expr) => {
        match var($a) {
            Err(_) => None,
            Ok(res) => match res.as_str() {
                "" => None,
                "0" => None,
                "false" => None,
                _ => Some($b),
            },
        }
    };
}
