//! Streamed response bodies: a bounded channel between a producer (usually a
//! thread the handler started) and the protocol engine that writes the bytes
//! out as they arrive.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

/// Bytes a producer may queue ahead of the connection before
/// [`BodySender::send`] blocks. Bounds memory when the client reads slowly.
const STREAM_BUFFER: usize = 256 * 1024;

/// Callback the engine registers so a runtime is told when a streamed body has
/// new data (or has ended) and the connection should be flushed.
pub(crate) type Waker = Arc<dyn Fn() + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// The producer is still writing.
    Open,
    /// The producer finished: the body is complete.
    Finished,
    /// The producer gave up: the body is incomplete and the response must be
    /// aborted rather than ended cleanly.
    Aborted,
}

struct State {
    queue: VecDeque<Vec<u8>>,
    queued: usize,
    end: End,
    /// Set once the receiving side is gone (response sent, dropped, or the
    /// client disconnected).
    rx_gone: bool,
    waker: Option<Waker>,
}

struct Shared {
    state: Mutex<State>,
    /// Signalled whenever the queue changes, the producer ends, or the
    /// receiver goes away. Used in both directions (backpressure and blocking
    /// collection).
    cond: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The producing half of a streamed response body, created by
/// [`Body::channel`](super::Body::channel).
///
/// Each [`send`](Self::send) (or [`Write::write`](io::Write::write)) is
/// delivered to the client as soon as the connection can take it: as an
/// HTTP/1.1 chunk, an HTTP/2 or HTTP/3 DATA frame, or raw bytes on an HTTP/1.0
/// connection (which is then closed to mark the end). Call
/// [`finish`](Self::finish) — or just drop the sender — to end the body
/// cleanly, or [`abort`](Self::abort) to cut the response short so the client
/// can tell it is incomplete. A sender dropped while its thread is panicking
/// aborts.
///
/// `send` blocks while more than a bounded amount of data is waiting to be
/// written, so a slow client slows the producer instead of growing memory. It
/// fails with [`io::ErrorKind::BrokenPipe`] once the client has gone away
/// (see [`is_closed`](Self::is_closed)).
pub struct BodySender {
    shared: Arc<Shared>,
    ended: bool,
}

impl std::fmt::Debug for BodySender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodySender")
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl BodySender {
    /// Queue `data` for the client, blocking while the buffer is full. Empty
    /// data is ignored.
    pub fn send(&self, data: impl Into<Vec<u8>>) -> io::Result<()> {
        let data = data.into();
        if data.is_empty() {
            return if self.is_closed() {
                Err(closed_error())
            } else {
                Ok(())
            };
        }
        let waker = {
            let mut st = self.shared.lock();
            while st.queued >= STREAM_BUFFER && !st.rx_gone {
                st = self.shared.cond.wait(st).unwrap_or_else(|e| e.into_inner());
            }
            if st.rx_gone {
                return Err(closed_error());
            }
            st.queued += data.len();
            st.queue.push_back(data);
            st.waker.clone()
        };
        self.shared.cond.notify_all();
        if let Some(w) = waker {
            w();
        }
        Ok(())
    }

    /// Whether the receiving side is gone: the client disconnected (or reset
    /// the stream), or the response was dropped without being sent. Further
    /// sends fail. Useful for a CGI-style `connection_aborted()`.
    pub fn is_closed(&self) -> bool {
        self.shared.lock().rx_gone
    }

    /// End the body cleanly. Equivalent to dropping the sender.
    pub fn finish(mut self) {
        self.end(End::Finished);
    }

    /// Abort the body: the response is cut short in a way the client can
    /// detect (an HTTP/1.1 chunked body without its terminating chunk and a
    /// closed connection, or a stream reset on HTTP/2 and HTTP/3).
    pub fn abort(mut self) {
        self.end(End::Aborted);
    }

    fn end(&mut self, how: End) {
        if self.ended {
            return;
        }
        self.ended = true;
        let waker = {
            let mut st = self.shared.lock();
            if st.end == End::Open {
                st.end = how;
            }
            st.waker.clone()
        };
        self.shared.cond.notify_all();
        if let Some(w) = waker {
            w();
        }
    }
}

impl io::Write for BodySender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Every write is already handed to the connection.
        Ok(())
    }
}

impl Drop for BodySender {
    fn drop(&mut self) {
        let how = if std::thread::panicking() {
            End::Aborted
        } else {
            End::Finished
        };
        self.end(how);
    }
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "response stream closed")
}

/// What a non-blocking read of a stream produced.
pub(crate) enum StreamPoll {
    /// Bytes ready to send.
    Data(Vec<u8>),
    /// Nothing ready yet; the producer is still writing.
    Pending,
    /// The producer finished; every byte has been handed out.
    End,
    /// The producer aborted.
    Aborted,
}

/// The receiving half, held (behind an `Arc`) by the response [`Body`]. When
/// the last clone is dropped the producer sees [`BodySender::is_closed`].
///
/// [`Body`]: super::Body
pub(crate) struct StreamReceiver {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for StreamReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamReceiver").finish_non_exhaustive()
    }
}

/// Create a connected sender/receiver pair.
pub(crate) fn channel() -> (BodySender, StreamReceiver) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            queue: VecDeque::new(),
            queued: 0,
            end: End::Open,
            rx_gone: false,
            waker: None,
        }),
        cond: Condvar::new(),
    });
    (
        BodySender {
            shared: Arc::clone(&shared),
            ended: false,
        },
        StreamReceiver { shared },
    )
}

impl StreamReceiver {
    /// Register the callback fired when new data arrives or the producer ends.
    pub(crate) fn set_waker(&self, waker: Waker) {
        self.shared.lock().waker = Some(waker);
    }

    /// Take whatever is queued, coalescing small writes up to about `max`
    /// bytes (a single larger write is returned whole). Never blocks.
    pub(crate) fn poll(&self, max: usize) -> StreamPoll {
        let polled = {
            let mut st = self.shared.lock();
            match st.queue.pop_front() {
                Some(mut out) => {
                    while let Some(next) = st.queue.front() {
                        if out.len() + next.len() > max {
                            break;
                        }
                        let next = st.queue.pop_front().unwrap();
                        out.extend_from_slice(&next);
                    }
                    st.queued -= out.len();
                    StreamPoll::Data(out)
                }
                None => match st.end {
                    End::Open => return StreamPoll::Pending,
                    End::Finished => return StreamPoll::End,
                    End::Aborted => return StreamPoll::Aborted,
                },
            }
        };
        // Room was freed: wake a producer blocked on backpressure.
        self.shared.cond.notify_all();
        polled
    }

    /// Block until the producer ends and return the whole body, or `Err(())`
    /// if it aborted. Used only where a buffered body is unavoidable (e.g.
    /// converting to an `http::Response<Vec<u8>>`).
    pub(crate) fn collect_blocking(&self) -> Result<Vec<u8>, ()> {
        let mut out = Vec::new();
        let mut st = self.shared.lock();
        loop {
            while let Some(chunk) = st.queue.pop_front() {
                st.queued -= chunk.len();
                out.extend_from_slice(&chunk);
            }
            self.shared.cond.notify_all();
            match st.end {
                End::Finished => return Ok(out),
                End::Aborted => return Err(()),
                End::Open => {
                    st = self.shared.cond.wait(st).unwrap_or_else(|e| e.into_inner());
                }
            }
        }
    }
}

impl Drop for StreamReceiver {
    fn drop(&mut self) {
        {
            let mut st = self.shared.lock();
            st.rx_gone = true;
            st.queue.clear();
            st.queued = 0;
            st.waker = None;
        }
        self.shared.cond.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn data_then_end() {
        let (tx, rx) = channel();
        tx.send(b"ab".to_vec()).unwrap();
        tx.send(b"cd".to_vec()).unwrap();
        match rx.poll(1024) {
            StreamPoll::Data(d) => assert_eq!(d, b"abcd"),
            _ => panic!("expected coalesced data"),
        }
        assert!(matches!(rx.poll(1024), StreamPoll::Pending));
        tx.finish();
        assert!(matches!(rx.poll(1024), StreamPoll::End));
    }

    #[test]
    fn coalescing_respects_max() {
        let (tx, rx) = channel();
        tx.send(vec![1u8; 10]).unwrap();
        tx.send(vec![2u8; 10]).unwrap();
        match rx.poll(15) {
            StreamPoll::Data(d) => assert_eq!(d.len(), 10),
            _ => panic!(),
        }
        match rx.poll(15) {
            StreamPoll::Data(d) => assert_eq!(d, vec![2u8; 10]),
            _ => panic!(),
        }
    }

    #[test]
    fn abort_is_reported() {
        let (tx, rx) = channel();
        tx.abort();
        assert!(matches!(rx.poll(16), StreamPoll::Aborted));
    }

    #[test]
    fn drop_finishes_and_panic_aborts() {
        let (tx, rx) = channel();
        drop(tx);
        assert!(matches!(rx.poll(16), StreamPoll::End));

        let (tx, rx) = channel();
        let _ = std::thread::spawn(move || {
            let _tx = tx;
            panic!("producer failed");
        })
        .join();
        assert!(matches!(rx.poll(16), StreamPoll::Aborted));
    }

    #[test]
    fn receiver_drop_closes_sender() {
        let (mut tx, rx) = channel();
        assert!(!tx.is_closed());
        drop(rx);
        assert!(tx.is_closed());
        assert_eq!(
            tx.write(b"x").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn waker_fires_on_send_and_end() {
        let (tx, rx) = channel();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = Arc::clone(&hits);
        rx.set_waker(Arc::new(move || {
            h.fetch_add(1, Ordering::SeqCst);
        }));
        tx.send(b"x".to_vec()).unwrap();
        tx.finish();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn backpressure_blocks_until_drained() {
        let (tx, rx) = channel();
        let producer = std::thread::spawn(move || {
            // Four buffers' worth: must block until the receiver drains.
            for _ in 0..4 {
                tx.send(vec![0u8; STREAM_BUFFER]).unwrap();
            }
        });
        let mut got = 0;
        while got < 4 * STREAM_BUFFER {
            match rx.poll(usize::MAX) {
                StreamPoll::Data(d) => got += d.len(),
                StreamPoll::Pending => std::thread::yield_now(),
                _ => break,
            }
        }
        producer.join().unwrap();
        assert_eq!(got, 4 * STREAM_BUFFER);
    }

    #[test]
    fn collect_blocking_waits_for_end() {
        let (tx, rx) = channel();
        let producer = std::thread::spawn(move || {
            tx.send(b"hello ".to_vec()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
            tx.send(b"world".to_vec()).unwrap();
        });
        assert_eq!(rx.collect_blocking().unwrap(), b"hello world");
        producer.join().unwrap();
    }
}
