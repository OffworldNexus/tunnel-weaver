//! Socket tuning the mux's scheduler depends on.

/// Disable Nagle's algorithm on a latency-sensitive socket.
///
/// The proxy writes a response head and its first body chunk as separate
/// small writes. With Nagle enabled, the second write is held until the first
/// is ACKed — a full RTT of added latency over a WAN, which delays the body
/// behind the head (and small mux control frames behind bulk data). Every
/// socket the tunnel owns is a latency path, so Nagle is turned off
/// everywhere.
pub fn set_tcp_nodelay(stream: &tokio::net::TcpStream) {
    let _ = stream.set_nodelay(true);
}

/// Set `TCP_NOTSENT_LOWAT` to ~32 KiB so the kernel reports writability
/// only when its own send queue is nearly empty. Without it, megabytes of
/// bulk data sit in the socket buffer ahead of an urgent frame and the
/// fair scheduler cannot help. Best effort and a no-op on platforms
/// without the option.
pub fn set_tcp_notsent_lowat(stream: &tokio::net::TcpStream) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let sock = socket2::SockRef::from(stream);
        let _ = sock.set_tcp_notsent_lowat(LOWAT);
    }
    #[cfg(target_vendor = "apple")]
    #[allow(unsafe_code)]
    {
        use std::os::fd::AsRawFd;
        // socket2 does not expose the option on Apple platforms; the
        // constant is TCP_NOTSENT_LOWAT from <netinet/tcp.h>.
        const TCP_NOTSENT_LOWAT: libc::c_int = 0x201;
        let val: libc::c_uint = LOWAT;
        // SAFETY: fd is a valid open socket owned by `stream` for the whole
        // call; the option value pointer and length describe `val` exactly.
        let _ = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                TCP_NOTSENT_LOWAT,
                (&val as *const libc::c_uint).cast(),
                std::mem::size_of_val(&val) as libc::socklen_t,
            )
        };
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    let _ = stream;
}

#[allow(dead_code)]
const LOWAT: u32 = 32 * 1024;
