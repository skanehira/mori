use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::sync::Notify;

/// Async task shutdown signaling mechanism combining Notify and AtomicBool
///
/// This struct provides a clean abstraction for coordinating async task shutdown by combining:
/// - `tokio::sync::Notify` for async wait/notify pattern
/// - `AtomicBool` for lock-free shutdown status checking
///
/// # Design rationale
/// Using only Notify has a timing issue: `notify_waiters()` only wakes tasks that have
/// already called `notified()`. The AtomicBool flag ensures we can check shutdown status
/// at any time, preventing missed notifications.
///
/// # Usage
/// ```no_run
/// use std::time::Duration;
/// # use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
/// # use tokio::sync::Notify;
/// # struct ShutdownSignal { notify: Notify, shutdown: AtomicBool }
/// # impl ShutdownSignal {
/// #     fn new() -> Arc<Self> { Arc::new(Self { notify: Notify::new(), shutdown: AtomicBool::new(false) }) }
/// #     async fn wait_timeout_or_shutdown(&self, timeout: Duration) -> bool {
/// #         if self.shutdown.load(Ordering::Relaxed) { return true; }
/// #         tokio::select! {
/// #             _ = self.notify.notified() => true,
/// #             _ = tokio::time::sleep(timeout) => self.shutdown.load(Ordering::Relaxed)
/// #         }
/// #     }
/// #     fn shutdown(&self) { self.shutdown.store(true, Ordering::Relaxed); self.notify.notify_waiters(); }
/// # }
/// # async fn example() {
/// let signal = ShutdownSignal::new();
///
/// // In worker task:
/// if signal.wait_timeout_or_shutdown(Duration::from_millis(1)).await {
///     // shutdown requested
/// }
///
/// // In main task:
/// signal.shutdown();
/// # }
/// ```
pub(super) struct ShutdownSignal {
    notify: Notify,
    shutdown: AtomicBool,
}

impl ShutdownSignal {
    /// Create a new ShutdownSignal
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            notify: Notify::new(),
            shutdown: AtomicBool::new(false),
        })
    }

    /// Wait for timeout or shutdown signal, whichever comes first
    ///
    /// Returns `true` if shutdown was signaled, `false` if timeout occurred
    pub async fn wait_timeout_or_shutdown(&self, timeout: Duration) -> bool {
        // Check shutdown flag first to avoid timing issues
        if self.shutdown.load(Ordering::Relaxed) {
            return true;
        }

        tokio::select! {
            _ = self.notify.notified() => true,
            _ = tokio::time::sleep(timeout) => {
                self.shutdown.load(Ordering::Relaxed)
            }
        }
    }

    /// Signal shutdown to waiting tasks
    ///
    /// Sets the shutdown flag and notifies all waiting tasks
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.notify.notify_waiters();
    }
}
