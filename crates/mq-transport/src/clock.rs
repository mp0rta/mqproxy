// spec §4.3 and §4.8
use crate::{Error, Inner};
use core::{cell::Cell, ptr};
use mq_transport_api::Time;

thread_local! {
    static NOW_US: Cell<u64> = const { Cell::new(0) };
    static LAST_US: Cell<u64> = const { Cell::new(0) };
    static OFFSET_US: Cell<i64> = const { Cell::new(0) };
    static CURRENT: Cell<*mut Inner> = const { Cell::new(ptr::null_mut()) };
    static ENGINE_PRESENT: Cell<bool> = const { Cell::new(false) };
}

/// Every call into xquic goes through here. `inner` is the stable Box<Inner> of the calling Transport.
/// CURRENT is cleared by an RAII guard, so a panic inside `f` (caught by a test's catch_unwind, or on the
/// way to an abort) never leaves a dangling CURRENT behind.
pub(crate) fn enter<R>(inner: *mut Inner, now: Time, f: impl FnOnce() -> R) -> R {
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            CURRENT.with(|c| c.set(ptr::null_mut()));
        }
    }
    LAST_US.with(|l| {
        debug_assert!(now.as_micros() >= l.get(), "time went backwards");
        l.set(now.as_micros());
    });
    NOW_US.with(|n| n.set(now.as_micros()));
    CURRENT.with(|c| c.set(inner));
    let _clear = Clear;
    f()
}

/// One engine per thread (§4.6); resets LAST_US for a fresh transport; sets the realtime offset.
pub(crate) fn claim_thread(offset_us: i64) -> Result<(), Error> {
    ENGINE_PRESENT.with(|p| {
        if p.replace(true) {
            Err(Error::EngineAlreadyOnThread)
        } else {
            Ok(())
        }
    })?;
    LAST_US.with(|l| l.set(0));
    OFFSET_US.with(|o| o.set(offset_us));
    Ok(())
}

pub(crate) fn release_thread() {
    ENGINE_PRESENT.with(|p| p.set(false));
}

/// Trampolines only: a raw pointer, never a &mut Transport.
pub(crate) fn current() -> *mut Inner {
    CURRENT.with(Cell::get)
}

pub(crate) extern "C" fn monotonic_ts() -> u64 {
    NOW_US.with(Cell::get)
}

pub(crate) extern "C" fn realtime_ts() -> u64 {
    (NOW_US.with(Cell::get) as i64 + OFFSET_US.with(Cell::get)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Releases the thread claim even if an assert fails.
    struct Released;
    impl Drop for Released {
        fn drop(&mut self) {
            release_thread();
        }
    }

    #[test]
    fn hook_reads_time_set_by_guard() {
        enter(ptr::null_mut(), Time(1234), || {
            assert_eq!(monotonic_ts(), 1234)
        });
    }

    #[test]
    fn realtime_adds_offset() {
        let _r = Released;
        claim_thread(1_000).unwrap();
        enter(ptr::null_mut(), Time(50), || {
            assert_eq!(realtime_ts(), 1_050)
        });
    }

    #[test]
    fn current_is_null_outside_guard() {
        assert!(current().is_null());
        let mut x = 0u8;
        let p = ptr::addr_of_mut!(x).cast::<Inner>();
        enter(p, Time(1), || assert_eq!(current(), p));
        assert!(current().is_null());
    }

    #[test]
    fn current_is_null_after_panic_inside_guard() {
        let mut x = 0u8;
        let p = ptr::addr_of_mut!(x).cast::<Inner>();
        let r = std::panic::catch_unwind(|| enter(p, Time(1), || panic!("boom")));
        assert!(r.is_err());
        assert!(current().is_null());
    }

    #[test]
    fn second_claim_fails_until_release() {
        let _r = Released;
        claim_thread(0).unwrap();
        assert_eq!(claim_thread(0), Err(Error::EngineAlreadyOnThread));
        release_thread();
        claim_thread(0).unwrap();
    }

    #[test]
    fn last_us_reset_by_claim() {
        let _r = Released;
        enter(ptr::null_mut(), Time(100), || {});
        claim_thread(0).unwrap();
        enter(ptr::null_mut(), Time(5), || {}); // would assert without the reset
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "time went backwards")]
    fn debug_assert_on_time_going_backwards() {
        enter(ptr::null_mut(), Time(10), || {});
        enter(ptr::null_mut(), Time(5), || {});
    }
}
