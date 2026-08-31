//! Fallback [`Platform`] for an OS that has no module yet.
//!
//! `macos.rs` is the only real implementation today. This stub exists so the
//! crate still *compiles* everywhere — `cargo publish`, docs.rs and a Linux
//! `cargo install` all need that — while every fact-gathering call refuses
//! honestly instead of inventing data. `main` checks [`super::UNSUPPORTED_OS`]
//! before probing, so this impl is a backstop rather than a path a user
//! normally reaches.

use super::{LinkInfo, Platform, PlatformError, ResolverInfo, RouteInfo, VpnInfo};

/// Refuses every query with [`PlatformError::Unsupported`].
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

    #[test]
    fn the_os_is_reported_as_unsupported() {
        assert!(super::super::UNSUPPORTED_OS.is_some());
    }
}
