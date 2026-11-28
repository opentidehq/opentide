//! The tenant codes a platform with its own client reports in place of the
//! generic ones (`tenant_unreachable`, ...), built in one place from the
//! platform's prefix (#1960).
//!
//! Bitdefender, Exabeam, Google SecOps and Graylog each report
//! `<platform>_tenant_unreachable`, `<platform>_tenant_unauthorized` and
//! `<platform>_request_failed`. The strings are a contract (`failure.code`,
//! `--json`, `opentide explain`), so they stay per platform; this table only
//! writes them once. Each code keeps its own page in
//! `src/opentide/data/diagnostics/`, which names the platform's settings.

/// One platform's tenant codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TenantCodes {
    /// The `--platform` name the codes start with.
    pub platform: &'static str,
    /// `<platform>_tenant_unreachable`: the tenant did not answer.
    pub unreachable: &'static str,
    /// `<platform>_tenant_unauthorized`: the tenant refused the credentials.
    pub unauthorized: &'static str,
    /// `<platform>_request_failed`: the tenant refused a request.
    pub request_failed: &'static str,
}

impl TenantCodes {
    /// The three codes, in the order of the fields.
    #[must_use]
    pub const fn codes(&self) -> [&'static str; 3] {
        [self.unreachable, self.unauthorized, self.request_failed]
    }
}

macro_rules! tenant_codes {
    ($($(#[$meta:meta])* $name:ident = $platform:literal;)*) => {
        $(
            $(#[$meta])*
            pub const $name: TenantCodes = TenantCodes {
                platform: $platform,
                unreachable: concat!($platform, "_tenant_unreachable"),
                unauthorized: concat!($platform, "_tenant_unauthorized"),
                request_failed: concat!($platform, "_request_failed"),
            };
        )*

        /// Every platform above, in declaration order.
        pub const ALL: &[TenantCodes] = &[$($name),*];
    };
}

tenant_codes! {
    /// Bitdefender GravityZone (`bitdefender`).
    BITDEFENDER = "bitdefender";
    /// Exabeam New-Scale SIEM (`exabeam`).
    EXABEAM = "exabeam";
    /// Google Security Operations (`google_secops`).
    GOOGLE_SECOPS = "google_secops";
    /// Graylog (`graylog`).
    GRAYLOG = "graylog";
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The strings as they were written by hand before this table: the table
    /// changes no code.
    #[test]
    fn the_codes_are_the_ones_each_platform_wrote_by_hand() {
        let dumped: Vec<&str> = ALL.iter().flat_map(TenantCodes::codes).collect();
        assert_eq!(
            dumped,
            [
                "bitdefender_tenant_unreachable",
                "bitdefender_tenant_unauthorized",
                "bitdefender_request_failed",
                "exabeam_tenant_unreachable",
                "exabeam_tenant_unauthorized",
                "exabeam_request_failed",
                "google_secops_tenant_unreachable",
                "google_secops_tenant_unauthorized",
                "google_secops_request_failed",
                "graylog_tenant_unreachable",
                "graylog_tenant_unauthorized",
                "graylog_request_failed",
            ]
        );
    }

    /// The platform modules' own constants, now read from the table, keep
    /// the strings they held.
    #[test]
    fn the_platform_constants_keep_their_strings() {
        assert_eq!(
            [
                crate::bitdefender::TENANT_UNREACHABLE,
                crate::bitdefender::TENANT_UNAUTHORIZED,
                crate::bitdefender::REQUEST_FAILED,
                crate::exabeam::UNREACHABLE,
                crate::exabeam::UNAUTHORIZED,
                crate::google_secops::auth::TENANT_UNAUTHORIZED,
                crate::graylog::TENANT_UNAUTHORIZED,
                crate::graylog::REQUEST_FAILED,
            ],
            [
                "bitdefender_tenant_unreachable",
                "bitdefender_tenant_unauthorized",
                "bitdefender_request_failed",
                "exabeam_tenant_unreachable",
                "exabeam_tenant_unauthorized",
                "google_secops_tenant_unauthorized",
                "graylog_tenant_unauthorized",
                "graylog_request_failed",
            ]
        );
    }

    #[test]
    fn every_code_starts_with_its_platform() {
        for codes in ALL {
            for code in codes.codes() {
                assert!(code.starts_with(&format!("{}_", codes.platform)), "{code}");
            }
        }
    }
}
