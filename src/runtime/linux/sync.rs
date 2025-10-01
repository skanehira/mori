use std::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Thread shutdown signaling mechanism combining Condvar and AtomicBool
///
/// This struct provides a clean abstraction for coordinating thread shutdown by combining:
/// - `Mutex<()>` and `Condvar` for wait/notify pattern
/// - `AtomicBool` for lock-free shutdown status checking
///
/// # Design rationale
/// Using only Condvar has a timing issue: `notify_all()` only wakes threads currently
/// in `wait()`. If a thread is processing between wait calls, it misses the notification.
/// The AtomicBool flag ensures the thread can check shutdown status at any time,
/// not just during wait.
///
/// # Usage
/// ```no_run
/// use std::time::Duration;
/// # use std::sync::{Arc, Mutex, Condvar, atomic::{AtomicBool, Ordering}};
/// # struct ShutdownSignal { lock: Mutex<()>, condvar: Condvar, shutdown: AtomicBool }
/// # impl ShutdownSignal {
/// #     fn new() -> Arc<Self> { Arc::new(Self { lock: Mutex::new(()), condvar: Condvar::new(), shutdown: AtomicBool::new(false) }) }
/// #     fn wait_timeout_or_shutdown(&self, timeout: Duration) -> bool {
/// #         let guard = self.lock.lock().unwrap();
/// #         let _result = self.condvar.wait_timeout(guard, timeout).unwrap();
/// #         self.shutdown.load(Ordering::Relaxed)
/// #     }
/// #     fn shutdown(&self) { self.shutdown.store(true, Ordering::Relaxed); self.condvar.notify_all(); }
/// # }
///
/// let signal = ShutdownSignal::new();
///
/// // In worker thread:
/// if signal.wait_timeout_or_shutdown(Duration::from_millis(1)) {
///     // shutdown requested
/// }
///
/// // In main thread:
/// signal.shutdown();
/// ```
pub(super) struct ShutdownSignal {
    lock: Mutex<()>,
    condvar: Condvar,
    shutdown: AtomicBool,
}

impl ShutdownSignal {
    /// Create a new ShutdownSignal
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            lock: Mutex::new(()),
            condvar: Condvar::new(),
            shutdown: AtomicBool::new(false),
        })
    }

    /// Wait for timeout or shutdown signal, whichever comes first
    ///
    /// Returns `true` if shutdown was signaled, `false` if timeout occurred
    pub(super) fn wait_timeout_or_shutdown(&self, timeout: Duration) -> bool {
        let guard = self.lock.lock().unwrap();
        let _result = self.condvar.wait_timeout(guard, timeout).unwrap();

        // Check shutdown flag after waking up
        // This ensures we catch shutdown even if notified during wait
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Signal shutdown to waiting threads
    ///
    /// Sets the shutdown flag and notifies all waiting threads
    pub(super) fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.condvar.notify_all();
    }
}
