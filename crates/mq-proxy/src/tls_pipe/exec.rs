// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP3 spec §7.1 / SP4 spec §2.1: hyper (and h2, rustls) is polled from the shard — one `Dirty` waker per
//! `Origin` and a single-thread executor; no tokio task or channel.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Wake};

/// The waker every hyper future and task is polled with: `wake` only sets the
/// flag (a `Waker` must be `Send + Sync`, so no `Rc`); the pump reads it.
#[derive(Debug, Default)]
pub struct Dirty(AtomicBool);

impl Dirty {
    pub fn set(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Reads and clears the flag.
    pub fn take(&self) -> bool {
        self.0.swap(false, Ordering::Relaxed)
    }

    /// Reads the flag, leaving it as it is.
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl Wake for Dirty {
    fn wake(self: Arc<Self>) {
        self.set();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.set();
    }
}

type Task = Pin<Box<dyn Future<Output = ()>>>;

/// spec §7.1: `execute` only pushes to `spawned` (hyper spawns from inside a
/// poll — the h2 `ClientTask` spawns its pipe tasks — so the polled set is
/// never borrowed at that moment); `poll_all` moves `spawned` into `tasks`
/// between polls. A clone is a spawn handle for hyper: it shares `spawned`
/// and owns no tasks — the tasks live in the `Origin`'s own instance.
#[derive(Default)]
pub struct ShardExec {
    spawned: Rc<RefCell<Vec<Task>>>,
    tasks: Vec<Task>,
}

impl Clone for ShardExec {
    fn clone(&self) -> Self {
        ShardExec {
            spawned: self.spawned.clone(),
            tasks: Vec::new(),
        }
    }
}

impl<F: Future<Output = ()> + 'static> hyper::rt::Executor<F> for ShardExec {
    fn execute(&self, fut: F) {
        self.spawned.borrow_mut().push(Box::pin(fut));
    }
}

impl ShardExec {
    /// Polls every task once, including those spawned during this call, and
    /// drops the finished ones. Returns whether anything changed (a task was
    /// spawned or finished) — an input to the pump's repeat rule (§7.3 step 4).
    pub fn poll_all(&mut self, cx: &mut Context<'_>) -> bool {
        let mut changed = false;
        let mut i = 0;
        loop {
            let mut fresh = std::mem::take(&mut *self.spawned.borrow_mut());
            changed |= !fresh.is_empty();
            self.tasks.append(&mut fresh);
            let Some(t) = self.tasks.get_mut(i) else {
                return changed;
            };
            if t.as_mut().poll(cx).is_ready() {
                // The last task moves to `i` and is polled next.
                drop(self.tasks.swap_remove(i));
                changed = true;
            } else {
                i += 1;
            }
        }
    }

    /// Tasks spawned and not yet finished (test-support accessor).
    #[cfg(any(test, feature = "test-support"))]
    pub fn len(&self) -> usize {
        self.tasks.len() + self.spawned.borrow().len()
    }

    /// Drops every task (§7.7 shutdown).
    pub fn clear(&mut self) {
        self.tasks.clear();
        // Dropped outside the borrow: a task's drop may reach `execute`.
        let s = std::mem::take(&mut *self.spawned.borrow_mut());
        drop(s);
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::rt::Executor;
    use std::cell::Cell;
    use std::task::{Poll, Waker};

    #[test]
    fn dirty_waker_sets_flag_and_is_send_sync() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<Dirty>();
        let d = Arc::new(Dirty::default());
        let w = Waker::from(d.clone());
        assert!(!d.take());
        w.wake_by_ref();
        assert!(d.take());
        assert!(!d.take(), "take clears");
        w.wake();
        assert!(d.take());
    }

    #[test]
    fn shard_exec_spawn_from_inside_poll_does_not_panic() {
        let mut exec = ShardExec::default();
        let handle = exec.clone();
        let inner_ran = Rc::new(Cell::new(false));
        let flag = inner_ran.clone();
        exec.execute(async move {
            let flag = flag.clone();
            // spawned while `poll_all` is polling this task
            handle.execute(async move { flag.set(true) });
        });
        let mut cx = Context::from_waker(Waker::noop());
        assert!(exec.poll_all(&mut cx));
        assert!(
            inner_ran.get(),
            "the task spawned inside a poll runs in the same call"
        );
        assert!(exec.is_empty());
    }

    #[test]
    fn exec_drops_finished_tasks() {
        let mut exec = ShardExec::default();
        let gate = Rc::new(Cell::new(false));
        let g = gate.clone();
        exec.execute(std::future::poll_fn(move |_| {
            if g.get() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }));
        exec.execute(async {});
        let mut cx = Context::from_waker(Waker::noop());
        assert!(exec.poll_all(&mut cx));
        assert_eq!(
            exec.len(),
            1,
            "the finished task is dropped, the pending one kept"
        );
        assert!(!exec.poll_all(&mut cx), "nothing changed");
        assert_eq!(exec.len(), 1);
        gate.set(true);
        assert!(exec.poll_all(&mut cx));
        assert!(exec.is_empty());
    }
}
