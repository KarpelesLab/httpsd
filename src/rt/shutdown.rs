//! A cooperative graceful-shutdown signal shared with the running server.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A cloneable handle used to ask a running server to shut down gracefully:
/// stop accepting new connections, let in-flight ones finish (up to a grace
/// period), then return from the `run*` call. Clone it freely — all clones
/// share one flag. Pass it to [`Server::graceful`] and trigger it from your own
/// signal handler / control plane.
///
/// [`Server::graceful`]: crate::Server::graceful
#[derive(Clone, Default)]
pub struct Shutdown {
    flag: Arc<AtomicBool>,
}
impl Shutdown {
    /// Create a fresh, untriggered handle.
    pub fn new() -> Shutdown {
        Shutdown::default()
    }
    /// Request graceful shutdown. Idempotent.
    pub fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
    /// Whether shutdown has been requested.
    pub fn is_triggered(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::Shutdown;

    #[test]
    fn starts_untriggered_and_triggers() {
        let s = Shutdown::new();
        assert!(!s.is_triggered());
        s.trigger();
        assert!(s.is_triggered());
        // Idempotent.
        s.trigger();
        assert!(s.is_triggered());
    }

    #[test]
    fn clones_share_one_flag() {
        let a = Shutdown::new();
        let b = a.clone();
        assert!(!b.is_triggered());
        // Triggering one clone is observed by the other.
        a.trigger();
        assert!(b.is_triggered());
        assert!(a.is_triggered());
    }
}
