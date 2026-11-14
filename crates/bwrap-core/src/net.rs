//! Bring up the loopback interface in a new network namespace, via rtnetlink.
//!
//! A faithful port of bubblewrap's `loopback_setup` (`network.c`): add
//! `127.0.0.1/8` to `lo` (`RTM_NEWADDR`) and set it `IFF_UP` (`RTM_NEWLINK`).
//! Only used with `--unshare-net`.
//!
//! bwrap builds the netlink messages with raw structs and pointer casts; here
//! they are assembled byte-by-byte in `Vec<u8>` (no `unsafe`), and sent over a
//! `nix` `NETLINK_ROUTE` socket.
//!
//! The many `as u16`/`as u8` casts convert kernel protocol constants
//! (`RTM_*`, `NLM_F_*`, `AF_*`, `IFA_*`, `IFF_UP`, scopes) and small, bounded
//! message lengths into their on-wire widths; the values definitionally fit, so
//! the truncation lint is expected file-wide (sign-loss does not arise here).
#![expect(
    clippy::cast_possible_truncation,
    reason = "kernel netlink/protocol constants and computed message lengths narrowed to their fixed-width on-wire fields"
)]

use std::os::fd::AsRawFd;

use nix::errno::Errno;
use nix::libc;
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, sendto,
    socket,
};

use crate::error::{Context, Error, Result};

/// Bring up `lo` in the current network namespace.
pub fn loopback_setup() -> Result<()> {
    // Keep the errno so the message matches C's `die_with_error`
    // ("...: <strerror>"). A zero index with no error maps to ENODEV, as glibc
    // leaves on a missing interface.
    let if_lo = match nix::net::if_::if_nametoindex("lo") {
        Ok(i) if i != 0 => i,
        Ok(_) => {
            return Err(Error::Sys {
                message: "loopback: Failed to look up lo".into(),
                errno: Errno::ENODEV,
            });
        }
        Err(e) => {
            return Err(Error::Sys {
                message: "loopback: Failed to look up lo".into(),
                errno: e,
            });
        }
    };

    let sock = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkRoute,
    )
    .context("loopback: Failed to create NETLINK_ROUTE socket")?;

    let pid = nix::unistd::getpid().as_raw().cast_unsigned();
    bind(sock.as_raw_fd(), &NetlinkAddr::new(pid, 0))
        .context("loopback: Failed to bind NETLINK_ROUTE socket")?;

    let mut seq: u32 = 0;

    // RTM_NEWADDR: add 127.0.0.1/8 to lo, scope host, permanent.
    let mut msg = NlMsg::new(
        libc::RTM_NEWADDR,
        (libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_ACK) as u16,
        next_seq(&mut seq),
        pid,
    );
    msg.push_ifaddrmsg(
        libc::AF_INET as u8,
        8,
        libc::IFA_F_PERMANENT as u8,
        libc::RT_SCOPE_HOST,
        if_lo,
    );
    let lo_be = libc::INADDR_LOOPBACK.to_be_bytes();
    msg.add_rta(libc::IFA_LOCAL, &lo_be);
    msg.add_rta(libc::IFA_ADDRESS, &lo_be);
    do_request(sock.as_raw_fd(), pid, &mut msg).context("loopback: Failed RTM_NEWADDR")?;

    // RTM_NEWLINK: set lo IFF_UP.
    let mut msg = NlMsg::new(
        libc::RTM_NEWLINK,
        libc::NLM_F_ACK as u16,
        next_seq(&mut seq),
        pid,
    );
    msg.push_ifinfomsg(if_lo, libc::IFF_UP as u32, libc::IFF_UP as u32);
    do_request(sock.as_raw_fd(), pid, &mut msg).context("loopback: Failed RTM_NEWLINK")?;

    Ok(())
}

fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_ne_bytes([b[off], b[off + 1]])
}

fn next_seq(seq: &mut u32) -> u32 {
    let s = *seq;
    *seq = seq.wrapping_add(1);
    s
}

/// A netlink message under construction, matching the C layout:
/// `nlmsghdr` (16 bytes) + payload + aligned `rtattr`s. `nlmsg_len` is written
/// on [`finish`](NlMsg::finish).
struct NlMsg {
    buf: Vec<u8>,
}

const NLMSG_HDRLEN: usize = 16;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

impl NlMsg {
    fn new(msg_type: u16, flags: u16, seq: u32, pid: u32) -> Self {
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        // nlmsg_len @0 set later; type @4, flags @6, seq @8, pid @12.
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&(flags | libc::NLM_F_REQUEST as u16).to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&pid.to_ne_bytes());
        Self { buf }
    }

    /// Append a `struct ifaddrmsg` (8 bytes).
    fn push_ifaddrmsg(&mut self, family: u8, prefixlen: u8, flags: u8, scope: u8, index: u32) {
        self.buf.push(family);
        self.buf.push(prefixlen);
        self.buf.push(flags);
        self.buf.push(scope);
        self.buf.extend_from_slice(&index.to_ne_bytes());
    }

    /// Append a `struct ifinfomsg` (16 bytes).
    fn push_ifinfomsg(&mut self, index: u32, flags: u32, change: u32) {
        self.buf.push(libc::AF_UNSPEC as u8); // ifi_family
        self.buf.push(0); // padding
        self.buf.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
        self.buf
            .extend_from_slice(&(index.cast_signed()).to_ne_bytes()); // ifi_index (i32)
        self.buf.extend_from_slice(&flags.to_ne_bytes());
        self.buf.extend_from_slice(&change.to_ne_bytes());
    }

    /// Append an `rtattr` (`RTA_LENGTH(data) = 4 + data.len()`), aligning the
    /// start to 4 bytes as the C does via `NLMSG_ALIGN(nlmsg_len)`.
    fn add_rta(&mut self, rta_type: u16, data: &[u8]) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        let rta_len = (4 + data.len()) as u16;
        self.buf.extend_from_slice(&rta_len.to_ne_bytes());
        self.buf.extend_from_slice(&rta_type.to_ne_bytes());
        self.buf.extend_from_slice(data);
        // bwrap does not pad the final nlmsg_len past the data (RTA_LENGTH, not
        // RTA_SPACE); the next add_rta re-aligns. The kernel reads by rta_len.
    }

    /// Write `nlmsg_len` and return the wire bytes.
    fn finish(&mut self) -> &[u8] {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        &self.buf
    }
}

/// Send `msg` to the kernel and read the ACK, matching `rtnl_do_request`.
/// Returns the failing errno so the caller can wrap it like bwrap's
/// `die_with_error("loopback: Failed RTM_...")`.
fn do_request(fd: std::os::fd::RawFd, pid: u32, msg: &mut NlMsg) -> std::result::Result<(), Errno> {
    let seq = u32::from_ne_bytes(msg.buf[8..12].try_into().expect("seq slice"));
    let wire = msg.finish();
    let kernel = NetlinkAddr::new(0, 0);
    let mut off = 0;
    while off < wire.len() {
        match sendto(fd, &wire[off..], &kernel, MsgFlags::empty()) {
            Ok(0) => return Err(Errno::EIO),
            Ok(n) => off += n,
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e),
        }
    }
    read_reply(fd, pid, seq)
}

/// The outcome of parsing one received datagram's worth of netlink messages.
#[derive(Debug, PartialEq, Eq)]
enum ReplyStatus {
    /// A terminal message was seen (`NLMSG_ERROR` code 0 or `NLMSG_DONE`): the
    /// request succeeded, stop reading.
    Done,
    /// This datagram held no terminal message; `recv` again.
    NeedMore,
}

/// Validate and interpret the netlink messages in one received buffer
/// (`rtnl_read_reply`'s inner walk), split out from the socket loop so every
/// branch — bounds guards, seq/pid mismatch, `NLMSG_ERROR`, `NLMSG_DONE`,
/// message advance — is unit-testable without a socket.
///
/// The message must be for our `pid` and `seq`; an `NLMSG_ERROR` with a nonzero
/// code (or any mismatch / malformed length) is a failure; `NLMSG_ERROR` with 0
/// or `NLMSG_DONE` is success. The kernel never sends a truncated or absurd
/// message, but a safe port must not panic on one, so lengths are bounds-checked
/// before any payload is indexed.
fn parse_reply_buf(buf: &[u8], pid: u32, seq: u32) -> std::result::Result<ReplyStatus, Errno> {
    let mut rest = buf;
    while rest.len() >= NLMSG_HDRLEN {
        let nlmsg_len = rd_u32(rest, 0) as usize;
        let nlmsg_type = rd_u16(rest, 4);
        let nlmsg_seq = rd_u32(rest, 8);
        let nlmsg_pid = rd_u32(rest, 12);
        if nlmsg_len < NLMSG_HDRLEN || nlmsg_len > rest.len() {
            return Err(Errno::EBADMSG);
        }
        if nlmsg_seq != seq || nlmsg_pid != pid {
            return Err(Errno::EBADMSG);
        }
        if nlmsg_type == libc::NLMSG_ERROR as u16 {
            // payload starts with an i32 error code (negative errno).
            if nlmsg_len < NLMSG_HDRLEN + 4 {
                return Err(Errno::EBADMSG);
            }
            let err = rd_u32(rest, NLMSG_HDRLEN).cast_signed();
            return if err == 0 {
                Ok(ReplyStatus::Done)
            } else {
                // wrapping_neg avoids an overflow panic on i32::MIN.
                Err(Errno::from_raw(err.wrapping_neg()))
            };
        }
        if nlmsg_type == libc::NLMSG_DONE as u16 {
            return Ok(ReplyStatus::Done);
        }
        // Advance by NLMSG_ALIGN(nlmsg_len); stop on a malformed length and
        // wait for the next datagram, as C does.
        let step = align4(nlmsg_len);
        if step == 0 || step > rest.len() {
            break;
        }
        rest = &rest[step..];
    }
    Ok(ReplyStatus::NeedMore)
}

/// Read datagrams until a terminal netlink message arrives, delegating the
/// per-buffer validation to [`parse_reply_buf`].
fn read_reply(fd: std::os::fd::RawFd, pid: u32, seq: u32) -> std::result::Result<(), Errno> {
    let mut buf = [0u8; 1024];
    loop {
        let received = match recv(fd, &mut buf, MsgFlags::empty()) {
            Ok(n) => n,
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(e),
        };
        match parse_reply_buf(&buf[..received], pid, seq)? {
            ReplyStatus::Done => return Ok(()),
            ReplyStatus::NeedMore => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newaddr_message_layout() {
        // Mirror the RTM_NEWADDR build and check the wire layout/length.
        let mut msg = NlMsg::new(libc::RTM_NEWADDR, 0, 7, 1234);
        msg.push_ifaddrmsg(
            libc::AF_INET as u8,
            8,
            libc::IFA_F_PERMANENT as u8,
            libc::RT_SCOPE_HOST,
            1,
        );
        let lo = libc::INADDR_LOOPBACK.to_be_bytes();
        msg.add_rta(libc::IFA_LOCAL, &lo);
        msg.add_rta(libc::IFA_ADDRESS, &lo);
        let wire = msg.finish();
        // 16 (hdr) + 8 (ifaddrmsg) + 8 (rta) + 8 (rta) = 40.
        assert_eq!(wire.len(), 40);
        assert_eq!(u32::from_ne_bytes(wire[0..4].try_into().unwrap()), 40);
        assert_eq!(
            u16::from_ne_bytes(wire[4..6].try_into().unwrap()),
            libc::RTM_NEWADDR
        );
        // NLM_F_REQUEST is always OR-ed in.
        assert_ne!(
            u16::from_ne_bytes(wire[6..8].try_into().unwrap()) & libc::NLM_F_REQUEST as u16,
            0
        );
        assert_eq!(u32::from_ne_bytes(wire[8..12].try_into().unwrap()), 7);
        // ifaddrmsg body at offset 16: family, prefixlen, flags, scope, index.
        assert_eq!(wire[16], libc::AF_INET as u8);
        assert_eq!(wire[17], 8); // prefixlen
        assert_eq!(wire[18], libc::IFA_F_PERMANENT as u8); // 0x80
        assert_eq!(wire[19], libc::RT_SCOPE_HOST); // 254
        assert_eq!(u32::from_ne_bytes(wire[20..24].try_into().unwrap()), 1); // index
        // First rtattr at offset 24: len=8, type=IFA_LOCAL.
        assert_eq!(u16::from_ne_bytes(wire[24..26].try_into().unwrap()), 8);
        assert_eq!(
            u16::from_ne_bytes(wire[26..28].try_into().unwrap()),
            libc::IFA_LOCAL
        );
        assert_eq!(&wire[28..32], &lo);
        // Second rtattr at offset 32: len=8, type=IFA_ADDRESS, data=lo.
        assert_eq!(u16::from_ne_bytes(wire[32..34].try_into().unwrap()), 8);
        assert_eq!(
            u16::from_ne_bytes(wire[34..36].try_into().unwrap()),
            libc::IFA_ADDRESS
        );
        assert_eq!(&wire[36..40], &lo);
    }

    #[test]
    fn newlink_message_layout() {
        let mut msg = NlMsg::new(libc::RTM_NEWLINK, 0, 1, 1);
        msg.push_ifinfomsg(1, libc::IFF_UP as u32, libc::IFF_UP as u32);
        let wire = msg.finish();
        assert_eq!(wire.len(), 32); // 16 + 16
        assert_eq!(u32::from_ne_bytes(wire[0..4].try_into().unwrap()), 32);
        assert_eq!(
            u16::from_ne_bytes(wire[4..6].try_into().unwrap()),
            libc::RTM_NEWLINK
        );
        // ifinfomsg body at offset 16: family(u8), pad, type(u16)=0,
        // index(i32), flags(u32), change(u32).
        assert_eq!(wire[16], libc::AF_UNSPEC as u8);
        assert_eq!(u16::from_ne_bytes(wire[18..20].try_into().unwrap()), 0); // ifi_type
        assert_eq!(i32::from_ne_bytes(wire[20..24].try_into().unwrap()), 1); // index
        assert_eq!(
            u32::from_ne_bytes(wire[24..28].try_into().unwrap()),
            libc::IFF_UP as u32
        ); // flags
        assert_eq!(
            u32::from_ne_bytes(wire[28..32].try_into().unwrap()),
            libc::IFF_UP as u32
        ); // change
    }

    #[test]
    fn align4_rounds_up() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(16), 16);
        assert_eq!(align4(17), 20);
    }

    // Build an nlmsghdr (+ optional payload) for the reply-parser tests.
    fn nlmsg(len: u32, msg_type: u16, seq: u32, pid: u32, payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&len.to_ne_bytes()); // nlmsg_len @0
        b.extend_from_slice(&msg_type.to_ne_bytes()); // type @4
        b.extend_from_slice(&0u16.to_ne_bytes()); // flags @6
        b.extend_from_slice(&seq.to_ne_bytes()); // seq @8
        b.extend_from_slice(&pid.to_ne_bytes()); // pid @12
        b.extend_from_slice(payload);
        b
    }

    const PID: u32 = 4242;
    const SEQ: u32 = 7;

    #[test]
    fn reply_error_code_zero_is_success() {
        let buf = nlmsg(20, libc::NLMSG_ERROR as u16, SEQ, PID, &0i32.to_ne_bytes());
        assert_eq!(parse_reply_buf(&buf, PID, SEQ), Ok(ReplyStatus::Done));
    }

    #[test]
    fn reply_done_is_success() {
        let buf = nlmsg(NLMSG_HDRLEN as u32, libc::NLMSG_DONE as u16, SEQ, PID, &[]);
        assert_eq!(parse_reply_buf(&buf, PID, SEQ), Ok(ReplyStatus::Done));
    }

    #[test]
    fn reply_error_nonzero_returns_that_errno() {
        // Kernel sends -errno; EEXIST is the realistic "already added" case.
        let code = -(Errno::EEXIST as i32);
        let buf = nlmsg(20, libc::NLMSG_ERROR as u16, SEQ, PID, &code.to_ne_bytes());
        assert_eq!(parse_reply_buf(&buf, PID, SEQ), Err(Errno::EEXIST));
    }

    #[test]
    fn reply_error_i32_min_does_not_panic() {
        // -2147483648 cannot be negated in i32; wrapping_neg must not panic.
        let buf = nlmsg(
            20,
            libc::NLMSG_ERROR as u16,
            SEQ,
            PID,
            &i32::MIN.to_ne_bytes(),
        );
        // Result is some errno; the point is it returns rather than panicking.
        assert!(parse_reply_buf(&buf, PID, SEQ).is_err());
    }

    #[test]
    fn reply_seq_or_pid_mismatch_is_ebadmsg() {
        let buf = nlmsg(20, libc::NLMSG_ERROR as u16, SEQ, PID, &0i32.to_ne_bytes());
        assert_eq!(parse_reply_buf(&buf, PID, SEQ + 1), Err(Errno::EBADMSG)); // seq
        assert_eq!(parse_reply_buf(&buf, PID + 1, SEQ), Err(Errno::EBADMSG)); // pid
    }

    #[test]
    fn reply_absurd_length_is_ebadmsg() {
        // nlmsg_len claims 9999 but the buffer is 20 bytes.
        let buf = nlmsg(
            9999,
            libc::NLMSG_ERROR as u16,
            SEQ,
            PID,
            &0i32.to_ne_bytes(),
        );
        assert_eq!(parse_reply_buf(&buf, PID, SEQ), Err(Errno::EBADMSG));
        // nlmsg_len smaller than a header is also rejected.
        let buf = nlmsg(4, libc::NLMSG_ERROR as u16, SEQ, PID, &0i32.to_ne_bytes());
        assert_eq!(parse_reply_buf(&buf, PID, SEQ), Err(Errno::EBADMSG));
    }

    #[test]
    fn reply_error_without_code_is_ebadmsg() {
        // NLMSG_ERROR header with no room for the i32 code.
        let buf = nlmsg(NLMSG_HDRLEN as u32, libc::NLMSG_ERROR as u16, SEQ, PID, &[]);
        assert_eq!(parse_reply_buf(&buf, PID, SEQ), Err(Errno::EBADMSG));
    }

    #[test]
    fn reply_short_buffer_wants_more() {
        // Fewer than 16 bytes: nothing to parse yet, read again.
        assert_eq!(
            parse_reply_buf(&[0u8; 8], PID, SEQ),
            Ok(ReplyStatus::NeedMore)
        );
        assert_eq!(parse_reply_buf(&[], PID, SEQ), Ok(ReplyStatus::NeedMore));
    }

    #[test]
    fn reply_advances_past_a_non_terminal_message() {
        // A leading non-ERROR/non-DONE message (type 16, aligned len 20),
        // followed by the terminal ACK, is skipped to reach the ACK.
        let mut first = nlmsg(20, 16, SEQ, PID, &0i32.to_ne_bytes());
        let ack = nlmsg(20, libc::NLMSG_ERROR as u16, SEQ, PID, &0i32.to_ne_bytes());
        first.extend_from_slice(&ack);
        assert_eq!(parse_reply_buf(&first, PID, SEQ), Ok(ReplyStatus::Done));
    }
}
