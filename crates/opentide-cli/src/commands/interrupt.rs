//! Ctrl-C on a network call: the one watch every command that talks to a
//! tenant (or the skills repository) puts around its request.

use opentide_connectors::ConnectorError;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// How often a press of Ctrl-C is looked for while a call runs.
const POLL: Duration = Duration::from_millis(50);

/// Runs *work* with Ctrl-C watched: a press cancels *cancel*, which the work
/// answers to (a runner stops its call on the tenant where the API allows
/// it) and ends with [`ConnectorError::Cancelled`].
pub async fn watched<T>(
    work: impl std::future::Future<Output = Result<T, ConnectorError>>,
    cancel: &CancellationToken,
    interrupted: &(dyn Fn() -> bool + Sync),
) -> Result<T, ConnectorError> {
    let watch = async {
        while !interrupted() {
            tokio::time::sleep(POLL).await;
        }
        cancel.cancel();
        std::future::pending::<()>().await;
    };
    tokio::select! {
        result = work => result,
        () = watch => Err(ConnectorError::Cancelled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run<T>(work: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(work)
    }

    #[test]
    fn work_that_finishes_is_not_cancelled() {
        let cancel = CancellationToken::new();
        let answer = run(watched(async { Ok(7) }, &cancel, &|| false));
        assert!(matches!(answer, Ok(7)));
        assert!(!cancel.is_cancelled());
    }

    #[test]
    fn a_press_cancels_the_token_and_ends_the_work() {
        let cancel = CancellationToken::new();
        // The work ends when the token is cancelled, as a runner's does, so
        // it only returns once the press has cancelled the token.
        let work = async {
            cancel.cancelled().await;
            Err::<(), _>(ConnectorError::Cancelled)
        };
        let answer = run(watched(work, &cancel, &|| true));
        assert!(matches!(answer, Err(ConnectorError::Cancelled)));
        assert!(cancel.is_cancelled());
    }
}
