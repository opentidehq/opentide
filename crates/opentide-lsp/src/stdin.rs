//! Stdin on WASI, read on the loop's own thread (wasip1 has no threads),
//! with a probe that tells, without waiting, whether the client sent more
//! while a request runs ([`crate::protocol::InputProbe`]): a workspace pull
//! then yields to it (#1767).
//!
//! The hosts answer the question in different ways. wasmtime's `poll_oneoff`
//! says when stdin has bytes; Node's (uvwasi) never does, but lets stdin be
//! read without waiting (`O_NONBLOCK`), which wasmtime refuses. The probe
//! asks `poll` first, then reads without waiting and keeps what it read for
//! the reader. A host that answers neither gets `false`: the pull runs to
//! its end, as it did before.
//!
//! stdin is read through its file descriptor (`rustix`), not `std`'s
//! buffered `Stdin`, so no byte waits in a buffer the probe cannot see.

use crate::protocol::InputProbe;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use std::io::{self, Read};
use std::sync::{Arc, Mutex, PoisonError};

/// What the probe read ahead of the reader.
type Ahead = Arc<Mutex<Vec<u8>>>;

/// stdin, the bytes the probe read ahead first.
pub(crate) struct ProbedStdin {
    ahead: Ahead,
}

impl ProbedStdin {
    /// The reader, and the probe that asks about its input.
    pub(crate) fn new() -> (Self, InputProbe) {
        let ahead = Ahead::default();
        let probed = Arc::clone(&ahead);
        (Self { ahead }, Arc::new(move || waiting(&probed)))
    }
}

impl Read for ProbedStdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        {
            let mut ahead = self.ahead.lock().unwrap_or_else(PoisonError::into_inner);
            if !ahead.is_empty() {
                let n = buf.len().min(ahead.len());
                buf[..n].copy_from_slice(&ahead[..n]);
                ahead.drain(..n);
                return Ok(n);
            }
        }
        let stdin = io::stdin();
        match rustix::io::read(&stdin, &mut *buf) {
            Err(error) if error == rustix::io::Errno::AGAIN => {
                // The probe could not put stdin back to waiting reads: put
                // it back here, and read again.
                if let Ok(flags) = fcntl_getfl(&stdin) {
                    let _ = fcntl_setfl(&stdin, flags - OFlags::NONBLOCK);
                }
                Ok(rustix::io::read(&stdin, buf)?)
            }
            read => Ok(read?),
        }
    }
}

/// Whether stdin has bytes to read now, never waiting for them.
fn waiting(ahead: &Ahead) -> bool {
    if !ahead
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_empty()
    {
        return true;
    }
    let stdin = io::stdin();
    let now = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut fds = [PollFd::new(&stdin, PollFlags::IN)];
    if poll(&mut fds, Some(&now)).is_ok_and(|ready| ready > 0) {
        return true;
    }
    // A host whose `poll` says nothing of stdin (Node's): read without
    // waiting, and keep what came.
    let Ok(flags) = fcntl_getfl(&stdin) else {
        return false;
    };
    if fcntl_setfl(&stdin, flags | OFlags::NONBLOCK).is_err() {
        return false;
    }
    let mut buf = vec![0; 16 * 1024];
    let read = rustix::io::read(&stdin, &mut buf);
    let _ = fcntl_setfl(&stdin, flags);
    match read {
        // The end of input: the loop reads it next.
        Ok(0) => true,
        Ok(n) => {
            buf.truncate(n);
            ahead
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(&buf);
            true
        }
        Err(_) => false,
    }
}
