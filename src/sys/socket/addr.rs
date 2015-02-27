use {NixResult, NixError, NixPath};
use super::{consts, sa_family_t};
use errno::Errno;
use libc;
use std::{fmt, hash, mem, net, ptr};
use std::ffi::{CStr, OsStr};
use std::net::{IpAddr, Ipv4Addr};
use std::num::Int;
use std::path::Path;
use std::os::unix::OsStrExt;

/*
 *
 * ===== AddressFamily =====
 *
 */

#[repr(i32)]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum AddressFamily {
    Unix = consts::AF_UNIX,
    Inet = consts::AF_INET,
    Inet6 = consts::AF_INET6,
}

#[derive(Copy)]
pub enum InetAddr {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

impl InetAddr {
    pub fn from_std(std: &net::SocketAddr) -> InetAddr {
        InetAddr::new(std.ip(), std.port())
    }

    pub fn new(ip: IpAddr, port: u16) -> InetAddr {
        match ip {
            IpAddr::V4(ref ip) => {
                let parts = ip.octets();
                let ip = (((parts[0] as u32) << 24) |
                          ((parts[1] as u32) << 16) |
                          ((parts[2] as u32) <<  8) |
                          ((parts[3] as u32) <<  0)).to_be();

                InetAddr::V4(libc::sockaddr_in {
                    sin_family: AddressFamily::Inet as sa_family_t,
                    sin_port: port.to_be(),
                    sin_addr: libc::in_addr { s_addr: ip },
                    .. unsafe { mem::zeroed() }
                })
            }
            IpAddr::V6(ref ip) => {
                let parts = ip.segments();

                InetAddr::V6(libc::sockaddr_in6 {
                    sin6_family: AddressFamily::Inet6 as sa_family_t,
                    sin6_port: port.to_be(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: [
                            parts[0].to_be(),
                            parts[1].to_be(),
                            parts[2].to_be(),
                            parts[3].to_be(),
                            parts[4].to_be(),
                            parts[5].to_be(),
                            parts[6].to_be(),
                            parts[7].to_be(),
                        ]
                    },
                    .. unsafe { mem::zeroed() }
                })
            }
        }
    }

    /// Gets the IP address associated with this socket address.
    pub fn ip(&self) -> IpAddr {
        match *self {
            InetAddr::V4(ref sa) => {
                let ip = Int::from_be(sa.sin_addr.s_addr);
                IpAddr::V4(Ipv4Addr::new(
                    ((ip >> 24) as u8) & 0xff,
                    ((ip >> 16) as u8) & 0xff,
                    ((ip >>  8) as u8) & 0xff,
                    ((ip >>  0) as u8) & 0xff))
            }
            InetAddr::V6(ref sa) => {
                let a: &[u16; 8] = &sa.sin6_addr.s6_addr;
                IpAddr::new_v6(
                    Int::from_be(a[0]),
                    Int::from_be(a[1]),
                    Int::from_be(a[2]),
                    Int::from_be(a[3]),
                    Int::from_be(a[4]),
                    Int::from_be(a[5]),
                    Int::from_be(a[6]),
                    Int::from_be(a[7]))
            }
        }
    }

    /// Gets the port number associated with this socket address
    pub fn port(&self) -> u16 {
        match *self {
            InetAddr::V6(ref sa) => Int::from_be(sa.sin6_port),
            InetAddr::V4(ref sa) => Int::from_be(sa.sin_port),
        }
    }

    pub fn to_std(&self) -> net::SocketAddr {
        net::SocketAddr::new(self.ip(), self.port())
    }

    pub fn to_str(&self) -> String {
        format!("{}", self)
    }
}

impl PartialEq for InetAddr {
    fn eq(&self, other: &InetAddr) -> bool {
        match (*self, *other) {
            (InetAddr::V4(ref a), InetAddr::V4(ref b)) => {
                a.sin_port == b.sin_port &&
                    a.sin_addr.s_addr == b.sin_addr.s_addr
            }
            (InetAddr::V6(ref a), InetAddr::V6(ref b)) => {
                a.sin6_port == b.sin6_port &&
                    a.sin6_addr.s6_addr == b.sin6_addr.s6_addr &&
                    a.sin6_flowinfo == b.sin6_flowinfo &&
                    a.sin6_scope_id == b.sin6_scope_id
            }
            _ => false,
        }
    }
}

impl Eq for InetAddr {
}

impl hash::Hash for InetAddr {
    fn hash<H: hash::Hasher>(&self, s: &mut H) {
        match *self {
            InetAddr::V4(ref a) => {
                ( a.sin_family,
                  a.sin_port,
                  a.sin_addr.s_addr ).hash(s)
            }
            InetAddr::V6(ref a) => {
                ( a.sin6_family,
                  a.sin6_port,
                  &a.sin6_addr.s6_addr,
                  a.sin6_flowinfo,
                  a.sin6_scope_id ).hash(s)
            }
        }
    }
}

impl Clone for InetAddr {
    fn clone(&self) -> InetAddr {
        *self
    }
}

impl fmt::Display for InetAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            InetAddr::V4(_) => write!(f, "{}:{}", self.ip(), self.port()),
            InetAddr::V6(_) => write!(f, "[{}]:{}", self.ip(), self.port()),
        }
    }
}

/*
 *
 * ===== UnixAddr =====
 *
 */

#[derive(Copy)]
pub struct UnixAddr(pub libc::sockaddr_un);

impl UnixAddr {
    pub fn new<P: ?Sized + NixPath>(path: &P) -> NixResult<UnixAddr> {
        try!(path.with_nix_path(|osstr| {
            unsafe {
                let bytes = osstr.as_bytes();

                let mut ret = libc::sockaddr_un {
                    sun_family: AddressFamily::Unix as sa_family_t,
                    .. mem::zeroed()
                };

                if bytes.len() >= ret.sun_path.len() {
                    return Err(NixError::Sys(Errno::ENAMETOOLONG));
                }

                ptr::copy_memory(
                    ret.sun_path.as_mut_ptr(),
                    bytes.as_ptr() as *const i8,
                    bytes.len());

                Ok(UnixAddr(ret))
            }
        }))
    }

    pub fn path(&self) -> &Path {
        unsafe {
            let bytes = CStr::from_ptr(self.0.sun_path.as_ptr()).to_bytes();
            Path::new(<OsStr as OsStrExt>::from_bytes(bytes))
        }
    }
}

impl PartialEq for UnixAddr {
    fn eq(&self, other: &UnixAddr) -> bool {
        unsafe {
            0 == libc::strcmp(self.0.sun_path.as_ptr(), other.0.sun_path.as_ptr())
        }
    }
}

impl Eq for UnixAddr {
}

impl hash::Hash for UnixAddr {
    fn hash<H: hash::Hasher>(&self, s: &mut H) {
        ( self.0.sun_family, self.path() ).hash(s)
    }
}

impl Clone for UnixAddr {
    fn clone(&self) -> UnixAddr {
        *self
    }
}

impl fmt::Display for UnixAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.path().display().fmt(f)
    }
}

/*
 *
 * ===== Sock addr =====
 *
 */

/// Represents a socket address
#[derive(Copy)]
pub enum SockAddr {
    Inet(InetAddr),
    Unix(UnixAddr)
}

impl SockAddr {
    pub fn new_inet(addr: InetAddr) -> SockAddr {
        SockAddr::Inet(addr)
    }

    pub fn new_unix<P: NixPath>(path: &P) -> NixResult<SockAddr> {
        Ok(SockAddr::Unix(try!(UnixAddr::new(path))))
    }

    pub fn family(&self) -> AddressFamily {
        match *self {
            SockAddr::Inet(InetAddr::V4(..)) => AddressFamily::Inet,
            SockAddr::Inet(InetAddr::V6(..)) => AddressFamily::Inet6,
            SockAddr::Unix(..) => AddressFamily::Unix,
        }
    }

    pub fn to_str(&self) -> String {
        format!("{}", self)
    }

    pub unsafe fn as_ffi_pair(&self) -> (&libc::sockaddr, libc::socklen_t) {
        match *self {
            SockAddr::Inet(InetAddr::V4(ref addr)) => (mem::transmute(addr), mem::size_of::<libc::sockaddr_in>() as libc::socklen_t),
            SockAddr::Inet(InetAddr::V6(ref addr)) => (mem::transmute(addr), mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t),
            SockAddr::Unix(UnixAddr(ref addr)) => (mem::transmute(addr), mem::size_of::<libc::sockaddr_un>() as libc::socklen_t),
        }
    }
}

impl PartialEq for SockAddr {
    fn eq(&self, other: &SockAddr) -> bool {
        match (*self, *other) {
            (SockAddr::Inet(ref a), SockAddr::Inet(ref b)) => {
                a == b
            }
            (SockAddr::Unix(ref a), SockAddr::Unix(ref b)) => {
                a == b
            }
            _ => false,
        }
    }
}

impl Eq for SockAddr {
}

impl hash::Hash for SockAddr {
    fn hash<H: hash::Hasher>(&self, s: &mut H) {
        match *self {
            SockAddr::Inet(ref a) => a.hash(s),
            SockAddr::Unix(ref a) => a.hash(s),
        }
    }
}

impl Clone for SockAddr {
    fn clone(&self) -> SockAddr {
        *self
    }
}

impl fmt::Display for SockAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SockAddr::Inet(ref inet) => inet.fmt(f),
            SockAddr::Unix(ref unix) => unix.fmt(f),
        }
    }
}
