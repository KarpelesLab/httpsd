//! TOML configuration loading.
//!
//! A [`ServerConfig`] mirrors the TOML file the CLI accepts. It can also be
//! turned directly into a runnable [`Server`](crate::rt::Server) when a runtime
//! feature is enabled.
//!
//! ```toml
//! listen = "0.0.0.0:8080"      # or ["127.0.0.1:8080", "[::1]:8080"]
//! root = "/var/www"            # document root for static file serving
//! server_name = "httpsd"
//! workers = 8
//!
//! [tls]
//! cert = "cert.pem"            # PEM chain (leaf first)
//! key = "key.pem"              # PEM private key
//! # self_signed = ["localhost"]  # alternatively, generate an ephemeral cert
//!
//! [compress]
//! enabled = true
//! min_size = 256
//! ```

use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{Error, Result};

/// Either a single value or a list of them (used for `listen`).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

/// TLS settings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to the PEM certificate chain (leaf first).
    pub cert: Option<String>,
    /// Path to the PEM private key.
    pub key: Option<String>,
    /// Generate an ephemeral self-signed certificate for these host names
    /// instead of loading `cert`/`key`.
    pub self_signed: Option<Vec<String>>,
}

/// Compression settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressConfig {
    /// Master switch (default `true`).
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Minimum body size to compress (default `256`).
    #[serde(default = "default_min_size")]
    pub min_size: usize,
}

fn yes() -> bool {
    true
}
fn default_min_size() -> usize {
    256
}

impl Default for CompressConfig {
    fn default() -> CompressConfig {
        CompressConfig {
            enabled: true,
            min_size: default_min_size(),
        }
    }
}

/// Automatic-certificate (ACME) settings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeFileConfig {
    /// Must be `true` to enable automatic issuance (accepts the CA's ToS).
    #[serde(default)]
    pub accept_tos: bool,
    /// Account contact email (optional).
    pub email: Option<String>,
    /// ACME directory URL (defaults to Let's Encrypt production).
    pub directory: Option<String>,
    /// Use the Let's Encrypt staging environment.
    #[serde(default)]
    pub staging: bool,
    /// Only issue for these host names, if set.
    pub host_whitelist: Option<Vec<String>>,
    /// Override the certificate storage directory.
    pub cert_dir: Option<PathBuf>,
}

/// `Strict-Transport-Security` settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HstsConfig {
    /// `max-age` in seconds (default one year).
    #[serde(default = "default_hsts_max_age")]
    pub max_age: u64,
    /// Append `; includeSubDomains`.
    #[serde(default)]
    pub include_subdomains: bool,
    /// Append `; preload`.
    #[serde(default)]
    pub preload: bool,
}

fn default_hsts_max_age() -> u64 {
    31_536_000
}

impl HstsConfig {
    /// Render the header value, e.g. `max-age=31536000; includeSubDomains`.
    pub fn header_value(&self) -> String {
        let mut v = format!("max-age={}", self.max_age);
        if self.include_subdomains {
            v.push_str("; includeSubDomains");
        }
        if self.preload {
            v.push_str("; preload");
        }
        v
    }
}

/// The parsed server configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Listen address(es).
    listen: OneOrMany,
    /// Document root for static file serving.
    pub root: Option<PathBuf>,
    /// `Server` header value.
    pub server_name: Option<String>,
    /// Worker thread count (thread-pool runtime).
    pub workers: Option<usize>,
    /// TLS settings.
    pub tls: Option<TlsConfig>,
    /// Compression settings.
    pub compress: Option<CompressConfig>,
    /// Serve content over plain HTTP instead of redirecting to HTTPS.
    #[serde(default)]
    pub allow_http: bool,
    /// Plain-HTTP listener address(es) for redirects + ACME HTTP-01.
    http_listen: Option<OneOrMany>,
    /// Automatic certificate management.
    pub acme: Option<AcmeFileConfig>,
    /// `Strict-Transport-Security` settings (sent on secure responses).
    pub hsts: Option<HstsConfig>,
}

impl ServerConfig {
    /// Parse a configuration from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<ServerConfig> {
        toml::from_str(s).map_err(|e| Error::Config(e.to_string()))
    }

    /// Read and parse a configuration file.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<ServerConfig> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| Error::Config(format!("reading {}: {e}", path.as_ref().display())))?;
        ServerConfig::from_toml_str(&text)
    }

    /// The configured listen addresses, as strings.
    pub fn listen_addrs(&self) -> Vec<String> {
        self.listen.clone().into_vec()
    }

    /// Build a runnable [`Server`](crate::rt::Server) from this configuration.
    #[cfg(any(feature = "rt-threadpool", feature = "rt-tokio", feature = "rt-mio"))]
    pub fn into_server(self) -> Result<crate::rt::Server> {
        let addrs = self.listen_addrs();
        let first = addrs
            .first()
            .ok_or_else(|| Error::Config("no listen address".into()))?;
        let mut server = crate::rt::Server::bind(first.as_str())?;

        if let Some(root) = &self.root {
            server = server.serve_dir(root.clone());
        }
        if let Some(workers) = self.workers {
            server = server.workers(workers);
        }
        if self.server_name.is_some() {
            server = server.server_name(self.server_name.clone());
        }

        if let Some(hsts) = &self.hsts {
            server = server.hsts(Some(hsts.header_value()));
        }
        if self.allow_http {
            server = server.allow_http(true);
        }
        if let Some(http) = &self.http_listen {
            use std::net::ToSocketAddrs;
            let mut resolved = Vec::new();
            for a in http.clone().into_vec() {
                resolved.extend(a.to_socket_addrs()?);
            }
            server = server.http_redirect(resolved.as_slice())?;
        }

        server = self.apply_tls(server)?;
        server = self.apply_compress(server);
        server = self.apply_acme(server)?;

        Ok(server)
    }

    #[cfg(all(
        feature = "acme",
        any(feature = "rt-threadpool", feature = "rt-tokio", feature = "rt-mio")
    ))]
    fn apply_acme(&self, server: crate::rt::Server) -> Result<crate::rt::Server> {
        let Some(acme) = &self.acme else {
            return Ok(server);
        };
        let directory = if acme.staging {
            crate::acme::client::LETSENCRYPT_STAGING.to_owned()
        } else {
            acme.directory
                .clone()
                .unwrap_or_else(|| crate::acme::client::LETSENCRYPT_PRODUCTION.to_owned())
        };
        let whitelist = acme.host_whitelist.as_ref().map(|hosts| {
            hosts
                .iter()
                .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
                .collect()
        });
        let cfg = crate::acme::AcmeConfig {
            directory_url: directory,
            accept_tos: acme.accept_tos,
            email: acme.email.clone(),
            host_whitelist: whitelist,
            cert_dir: acme.cert_dir.clone(),
        };
        Ok(server.acme(crate::acme::AcmeManager::new(cfg)?))
    }

    #[cfg(all(
        not(feature = "acme"),
        any(feature = "rt-threadpool", feature = "rt-tokio", feature = "rt-mio")
    ))]
    fn apply_acme(&self, server: crate::rt::Server) -> Result<crate::rt::Server> {
        if self.acme.is_some() {
            return Err(Error::Config(
                "[acme] configured but the `acme` feature is not enabled".into(),
            ));
        }
        Ok(server)
    }

    #[cfg(all(
        feature = "tls",
        any(feature = "rt-threadpool", feature = "rt-tokio", feature = "rt-mio")
    ))]
    fn apply_tls(&self, server: crate::rt::Server) -> Result<crate::rt::Server> {
        let Some(tls) = &self.tls else {
            return Ok(server);
        };
        let acceptor = match (&tls.cert, &tls.key, &tls.self_signed) {
            (Some(cert), Some(key), _) => crate::tls::TlsAcceptor::from_pem_files(cert, key)?,
            (_, _, Some(names)) => {
                let refs: Vec<&str> = names.iter().map(String::as_str).collect();
                crate::tls::TlsAcceptor::self_signed(&refs)?
            }
            _ => {
                return Err(Error::Config(
                    "[tls] requires either cert+key or self_signed".into(),
                ));
            }
        };
        Ok(server.tls(acceptor))
    }

    #[cfg(all(
        not(feature = "tls"),
        any(feature = "rt-threadpool", feature = "rt-tokio", feature = "rt-mio")
    ))]
    fn apply_tls(&self, server: crate::rt::Server) -> Result<crate::rt::Server> {
        if self.tls.is_some() {
            return Err(Error::Config(
                "[tls] configured but the `tls` feature is not enabled".into(),
            ));
        }
        Ok(server)
    }

    #[cfg(all(
        feature = "compress",
        any(feature = "rt-threadpool", feature = "rt-tokio", feature = "rt-mio")
    ))]
    fn apply_compress(&self, server: crate::rt::Server) -> crate::rt::Server {
        let c = self.compress.clone().unwrap_or_default();
        server.compression(crate::compress::Options {
            enabled: c.enabled,
            min_size: c.min_size,
        })
    }

    #[cfg(all(
        not(feature = "compress"),
        any(feature = "rt-threadpool", feature = "rt-tokio", feature = "rt-mio")
    ))]
    fn apply_compress(&self, server: crate::rt::Server) -> crate::rt::Server {
        server
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal() {
        let cfg = ServerConfig::from_toml_str("listen = \"127.0.0.1:8080\"\nroot = \"/srv\"\n")
            .unwrap();
        assert_eq!(cfg.listen_addrs(), vec!["127.0.0.1:8080"]);
        assert_eq!(cfg.root, Some(PathBuf::from("/srv")));
    }

    #[test]
    fn parses_full() {
        let toml = r#"
            listen = ["127.0.0.1:8443", "[::1]:8443"]
            root = "/var/www"
            workers = 16

            [tls]
            self_signed = ["localhost"]

            [compress]
            enabled = false
            min_size = 1024
        "#;
        let cfg = ServerConfig::from_toml_str(toml).unwrap();
        assert_eq!(cfg.listen_addrs().len(), 2);
        assert_eq!(cfg.workers, Some(16));
        assert!(cfg.tls.is_some());
        assert!(!cfg.compress.as_ref().unwrap().enabled);
    }
}
