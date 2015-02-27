
use {NixResult, NixError};
use super::addr::InetAddr;
use super::consts;
use libc::in_addr;
use std::fmt;

#[repr(C)]
#[derive(Copy)]
pub struct ip_mreq {
    pub imr_multiaddr: in_addr,
    pub imr_interface: in_addr,
}

impl fmt::Debug for ip_mreq {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "ip_mreq {{ imr_multiaddr: {{ s_addr: 0x{:x} }}, imr_interface: {{ s_addr: 0x{:x} }} }}",
                    self.imr_multiaddr.s_addr, self.imr_interface.s_addr)
    }
}

impl ip_mreq {
    pub fn new(group: &InetAddr, interface: Option<&InetAddr>) -> NixResult<ip_mreq> {
        // Map the group to an in_addr
        let group = match *group {
            InetAddr::V4(group) => group.sin_addr,
            _ => return Err(NixError::invalid_argument()),
        };

        // Map the interface to an in_addr
        let interface = match interface {
            Some(&InetAddr::V4(interface)) => interface.sin_addr,
            Some(&InetAddr::V6(..)) => return Err(NixError::invalid_argument()),
            None => in_addr { s_addr: consts::INADDR_ANY },
        };

        Ok(ip_mreq {
            imr_multiaddr: group,
            imr_interface: interface,
        })
    }
}
