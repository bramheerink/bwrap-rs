//! A global allocator that mirrors bubblewrap's out-of-memory behaviour.
//!
//! bubblewrap's `xmalloc`/`xcalloc`/`xrealloc`/`xstrdup` (`utils.c`) funnel a
//! failed allocation into `die_oom`: `fputs ("Out of memory\n", stderr);
//! exit (1);`. Rust's default on allocation failure is `handle_alloc_error`,
//! which prints `memory allocation of N bytes failed` and `abort()`s — with
//! `panic = "abort"` that is SIGABRT (exit 134) and a core dump, not exit 1.
//!
//! [`OomExit`] wraps the system allocator and, on a null return, writes exactly
//! `Out of memory\n` to fd 2 and `_exit(1)`s — byte-identical to `die_oom`, so a
//! sandbox launched under a tight `ulimit -v` / `LimitAS=` refuses to start the
//! same way the C tool does instead of crashing. Registered with
//! `#[global_allocator]` in the `bwrap` binary; `std::alloc::set_alloc_error_hook`
//! is not stable, which is why the allocator wrapper is the route.

use std::alloc::{GlobalAlloc, Layout, System};

/// The system allocator, except a failed allocation exits 1 with `die_oom`'s
/// message instead of aborting.
#[derive(Debug)]
pub struct OomExit;

// SAFETY: every method forwards to `System` (a sound `GlobalAlloc`) with the
// same arguments and only adds a null-return check that diverges via `_exit`, so
// it upholds every `GlobalAlloc` contract `System` does.
unsafe impl GlobalAlloc for OomExit {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded verbatim to the system allocator.
        let p = unsafe { System.alloc(layout) };
        if p.is_null() {
            die_oom();
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded verbatim to the system allocator.
        let p = unsafe { System.alloc_zeroed(layout) };
        if p.is_null() {
            die_oom();
        }
        p
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded verbatim to the system allocator. On a null return
        // the original `ptr` is untouched (still owned by the caller); we exit
        // immediately, so leaking it is moot.
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if p.is_null() {
            die_oom();
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded verbatim to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Write `Out of memory\n` to stderr and `_exit(1)`, exactly as bubblewrap's
/// `die_oom`. Allocation-free and async-signal-safe (we are out of memory).
#[cold]
#[inline(never)]
fn die_oom() -> ! {
    const MSG: &[u8] = b"Out of memory\n";
    let mut off = 0usize;
    while off < MSG.len() {
        let rest = &MSG[off..];
        // SAFETY: `write(2, buf, len)` with a valid pointer/length into a static;
        // a raw syscall that touches no Rust-owned memory. Partial writes and
        // EINTR are retried; any hard error just falls through to `_exit`.
        let n = unsafe { nix::libc::write(2, rest.as_ptr().cast(), rest.len()) };
        if n <= 0 {
            break;
        }
        off += n.cast_unsigned();
    }
    // SAFETY: `_exit` takes a plain int, touches no memory of ours, never returns.
    unsafe { nix::libc::_exit(1) }
}
