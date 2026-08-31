//! Fallback [`Platform`] for an OS with no module yet.
//!
//! Exists so the crate compiles off macOS — crates.io and docs.rs both build
//! there. Every query refuses rather than inventing a reading.

use super::{LinkInfo, Platform, PlatformError, ResolverInfo, RouteInfo, VpnInfo};

pub struct Unsupported;

impl Platform for Unsupported {
    fn route(&self) -> Result<RouteInfo, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    fn link(&self, _interface: &str) -> Result<LinkInfo, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    fn resolvers(&self) -> Result<ResolverInfo, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    fn vpn(&self) -> Result<VpnInfo, PlatformError> {
        Err(PlatformError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_query_refuses_rather_than_inventing_data() {
        let p = Unsupported;
        assert!(matches!(p.route(), Err(PlatformError::Unsupported)));
        assert!(matches!(p.link("en0"), Err(PlatformError::Unsupported)));
        assert!(matches!(p.resolvers(), Err(PlatformError::Unsupported)));
        assert!(matches!(p.vpn(), Err(PlatformError::Unsupported)));
    }

    /// Guards against the two `cfg` gates drifting: this module compiling while
    /// `UNSUPPORTED_OS` still claims the OS is supported would skip the refusal.
    #[test]
    fn the_os_is_reported_as_unsupported() {
        assert!(crate::platform::UNSUPPORTED_OS.is_some());
    }
}
