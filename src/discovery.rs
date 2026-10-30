//! mDNS advertisement of `_arrowbridge._tcp.local.` so a phone on the same network finds the
//! machine by name. Discovery finds the address, never the key: the TXT record carries a display
//! name and whether pairing is required, nothing else (it is broadcast in cleartext).
//!
//! Difference from the Python: it advertised EVERY local IPv4 address; this advertises only the
//! address the server is actually bound to, because the others do not listen.

#[cfg(feature = "mdns")]
pub struct Advertiser {
    daemon: mdns_sd::ServiceDaemon,
    fullname: String,
}

pub const SERVICE_TYPE: &str = "_arrowbridge._tcp.local.";

#[cfg(feature = "mdns")]
impl Advertiser {
    pub fn start(bind: std::net::IpAddr, port: u16, name: &str) -> Result<Advertiser, String> {
        let daemon = mdns_sd::ServiceDaemon::new().map_err(|e| format!("{e}"))?;
        let host = format!("{}.local.", crate::config::hostname());
        let props = [("name", name), ("pair_required", "1")];
        let info = mdns_sd::ServiceInfo::new(SERVICE_TYPE, name, &host, bind, port, &props[..])
            .map_err(|e| format!("{e}"))?;
        let fullname = info.get_fullname().to_string();
        daemon.register(info).map_err(|e| format!("{e}"))?;
        crate::log::event("mdns_advertising");
        Ok(Advertiser { daemon, fullname })
    }

    pub fn stop(self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}
