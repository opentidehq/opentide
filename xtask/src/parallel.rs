//! Independent work on every core, reported in a fixed order (#841): the
//! comparisons CI runs over hundreds of cases (`golden check`, `lsp parity`)
//! printed their results one case at a time, on one core.

use std::num::NonZero;
use std::sync::atomic::{AtomicUsize, Ordering};

/// `work` on every item, on as many threads as the machine has cores; the
/// results in the items' order, whichever thread finished first.
///
/// # Panics
///
/// A panic in `work` is raised again here, once every thread has stopped.
pub fn in_order<T: Sync, R: Send>(items: &[T], work: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism()
        .map_or(2, NonZero::get)
        .min(items.len().max(1));
    let mut results: Vec<(usize, R)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let at = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(at) else { break };
                        done.push((at, work(item)));
                    }
                    done
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    });
    results.sort_by_key(|(at, _)| *at);
    results.into_iter().map(|(_, result)| result).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_results_are_in_the_items_order() {
        let items: Vec<u64> = (0..200).collect();
        let squares = super::in_order(&items, |n| {
            // Uneven work, so the threads finish out of order.
            std::thread::sleep(std::time::Duration::from_micros(200 - n));
            n * n
        });
        assert_eq!(squares, items.iter().map(|n| n * n).collect::<Vec<_>>());
        assert!(super::in_order(&[] as &[u64], |n| *n).is_empty());
    }
}
