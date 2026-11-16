//! Independent work on every core, reported in a fixed order (#841): the
//! comparisons CI runs over hundreds of cases (`golden check`, `lsp parity`)
//! printed their results one case at a time, on one core.
//!
//! The items run on a pool of their own, never on rayon's global pool: an
//! item may wait on a thread of its own (the language server loads the
//! workspace on one) whose work is on the global pool, and with every global
//! thread waiting in an item, that work would never start.

use rayon::prelude::*;

/// `work` on every item, on as many threads as the machine has cores; the
/// results in the items' order, whichever thread finished first.
///
/// # Panics
///
/// A panic in `work` is raised again here, once every thread has stopped.
pub fn in_order<T: Sync, R: Send>(items: &[T], work: impl Fn(&T) -> R + Sync + Send) -> Vec<R> {
    let threads = std::thread::available_parallelism().map_or(2, std::num::NonZero::get);
    in_order_on(threads, items, work)
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
        Ok(pool) => pool.install(|| items.par_iter().map(work).collect()),
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
    fn an_item_may_wait_on_work_of_the_global_pool() {
        use rayon::prelude::*;
        // More items than the global pool has threads, each waiting on a
        // thread of its own whose work is on the global pool (as the
        // language server's workspace load is): on the global pool every
        // thread would wait in an item and that work would never start.
        let items: Vec<u64> = (0..=rayon::current_num_threads() as u64).collect();
        let sums = super::in_order(&items, |n| {
            let n = *n;
            std::thread::spawn(move || (0..=n).into_par_iter().sum::<u64>())
                .join()
                .unwrap()
        });
        assert_eq!(
            sums,
            items.iter().map(|n| n * (n + 1) / 2).collect::<Vec<_>>()
        );
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
