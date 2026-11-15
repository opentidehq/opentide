//! Independent work on every core, reported in a fixed order (#841): the
//! comparisons CI runs over hundreds of cases (`golden check`, `lsp parity`)
//! printed their results one case at a time, on one core.

use rayon::prelude::*;

/// `work` on every item, on as many threads as the machine has cores; the
/// results in the items' order, whichever thread finished first.
///
/// # Panics
///
/// A panic in `work` is raised again here, once every thread has stopped.
pub fn in_order<T: Sync, R: Send>(items: &[T], work: impl Fn(&T) -> R + Sync + Send) -> Vec<R> {
    items.par_iter().map(work).collect()
}

/// [`in_order`] on `threads` threads (at least one), as `--jobs N` asks.
///
/// # Panics
///
/// A panic in `work` is raised again here, once every thread has stopped.
pub fn in_order_on<T: Sync, R: Send>(
    threads: usize,
    items: &[T],
    work: impl Fn(&T) -> R + Sync + Send,
) -> Vec<R> {
    match rayon::ThreadPoolBuilder::new()
        .num_threads(threads.clamp(1, items.len().max(1)))
        .build()
    {
        Ok(pool) => pool.install(|| in_order(items, work)),
        // The system would not give threads: the work still gets done.
        Err(_) => items.iter().map(work).collect(),
    }
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

    #[test]
    fn a_job_count_bounds_the_threads_and_keeps_the_order() {
        let items: Vec<u64> = (0..50).collect();
        for threads in [0, 1, 3, 500] {
            let seen = std::sync::Mutex::new(std::collections::HashSet::new());
            let doubled = super::in_order_on(threads, &items, |n| {
                seen.lock().unwrap().insert(std::thread::current().id());
                std::thread::sleep(std::time::Duration::from_micros(300));
                n * 2
            });
            assert_eq!(doubled, items.iter().map(|n| n * 2).collect::<Vec<_>>());
            assert!(seen.lock().unwrap().len() <= threads.max(1), "{threads}");
        }
    }
}
