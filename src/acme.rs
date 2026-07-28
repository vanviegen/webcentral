use anyhow::{Context, Result};
use instant_acme::{Account, ChallengeType, Identifier, NewAccount, NewOrder};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct CertManager {
    config_dir: PathBuf,
    email: String,
    acme_url: String,
    account: Arc<RwLock<Option<Account>>>,
    // Store pending challenges: domain -> (token, key_authorization)
    pub challenges: Arc<RwLock<std::collections::HashMap<String, (String, String)>>>,
}

impl std::fmt::Debug for CertManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertManager")
            .field("config_dir", &self.config_dir)
            .field("email", &self.email)
            .field("acme_url", &self.acme_url)
            .finish()
    }
}

impl CertManager {
    pub fn new(config_dir: PathBuf, email: String, acme_url: String) -> Self {
        fs::create_dir_all(&config_dir).ok();
        fs::create_dir_all(config_dir.join("certs")).ok();
        fs::create_dir_all(config_dir.join("keys")).ok();

        Self {
            config_dir,
            email,
            acme_url,
            account: Arc::new(RwLock::new(None)),
            challenges: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    async fn get_or_create_account(&self) -> Result<Account> {
        let mut account_lock = self.account.write().await;

        if let Some(ref account) = *account_lock {
            return Ok(account.clone());
        }

        // Create new account (or get existing if already created with this email)
        let result = Account::builder()?
            .create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", self.email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.acme_url.clone(),
                None,
            )
            .await;
        
        let (account, _credentials) = match result {
            Ok(acc) => acc,
            Err(e) => {
                eprintln!("Failed to create ACME account ({}): {:?}", self.email, e);
                return Err(e.into());
            }
        };
        *account_lock = Some(account.clone());
        Ok(account)
    }

    /// Register an HTTP-01 challenge response for every identifier in the order and tell the ACME
    /// server we're ready to be validated. Tokens are pushed onto `tokens` as they are registered,
    /// so the caller can clean them all up even when this fails partway.
    async fn setup_challenges(&self, order: &mut instant_acme::Order, tokens: &mut Vec<String>) -> Result<()> {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.context("Failed to get authorization")?;
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .context("No HTTP-01 challenge offered")?;

            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization();

            // Store challenge for the HTTP-01 server to serve
            self.challenges.write().await.insert(token.clone(), (token.clone(), key_auth.as_str().to_string()));
            tokens.push(token);

            challenge.set_ready().await.context("Failed to set challenge ready")?;
        }
        Ok(())
    }

    /// Acquire a certificate covering `domains`, saved under the first of them.
    pub async fn acquire_certificate(&self, domains: &[String]) -> Result<()> {
        let primary = &domains[0];
        let account = self.get_or_create_account().await?;

        let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .with_context(|| format!("Failed to create ACME order for {}", domains.join(" and ")))?;

        let mut tokens = Vec::new();
        let setup_result = self.setup_challenges(&mut order, &mut tokens).await;

        // Wait for the order to be ready (this is when the ACME server validates the challenges)
        use instant_acme::RetryPolicy;
        let poll_result = match setup_result {
            Ok(()) => order
                .poll_ready(&RetryPolicy::default())
                .await
                .context("Failed to poll order ready - this usually means the HTTP-01 challenge failed. Check that DNS points to this server and port 80 is accessible."),
            Err(e) => Err(e),
        };

        // Clean up our challenges, whether or not validation succeeded
        for token in &tokens {
            self.challenges.write().await.remove(token);
        }
        poll_result?;

        // Finalize order - this generates the private key and returns it
        let private_key_pem = order
            .finalize()
            .await
            .context("Failed to finalize order - the order may be in an invalid state")?;

        // Poll for certificate
        let cert_chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .context("Failed to poll for certificate")?;

        let cert_path = self.config_dir.join("certs").join(format!("{}.pem", primary));
        let key_path = self.config_dir.join("keys").join(format!("{}.pem", primary));
        fs::write(&cert_path, &cert_chain_pem)?;
        fs::write(&key_path, &private_key_pem)?;

        Ok(())
    }

    pub fn get_certificate(
        &self,
        domain: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let cert_path = self.config_dir.join("certs").join(format!("{}.pem", domain));
        let key_path = self.config_dir.join("keys").join(format!("{}.pem", domain));

        if !cert_path.exists() || !key_path.exists() {
            anyhow::bail!("Certificate not found for domain: {}", domain);
        }

        // Load certificate chain
        let cert_data = fs::read(&cert_path)?;
        let certs = rustls_pemfile::certs(&mut &cert_data[..]).collect::<Result<Vec<_>, _>>()?;

        // Load private key
        let key_data = fs::read(&key_path)?;
        let key =
            rustls_pemfile::private_key(&mut &key_data[..])?.context("No private key found")?;

        Ok((certs, key))
    }



    pub async fn get_challenge(&self, token: &str) -> Option<String> {
        let challenges = self.challenges.read().await;
        challenges.get(token).map(|(_, key_auth)| key_auth.clone())
    }

    /// Expiration time and the DNS names covered by the certificate stored under `domain`.
    pub fn get_certificate_info(&self, domain: &str) -> Result<(std::time::SystemTime, Vec<String>)> {
        let cert_path = self.config_dir.join("certs").join(format!("{}.pem", domain));

        if !cert_path.exists() {
            anyhow::bail!("Certificate not found for domain: {}", domain);
        }

        let cert_data = fs::read(&cert_path)?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(&cert_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse PEM: {}", e))?;

        let cert = pem.parse_x509()
            .map_err(|e| anyhow::anyhow!("Failed to parse X.509 certificate: {}", e))?;

        // x509-parser returns ASN1Time, via OffsetDateTime to std::time::SystemTime
        let expiration = cert.validity().not_after.to_datetime();
        let expiration = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(expiration.unix_timestamp() as u64);

        let names = cert
            .subject_alternative_name()?
            .map(|san| san.value.general_names.iter()
                .filter_map(|name| match name {
                    x509_parser::extensions::GeneralName::DNSName(name) => Some(name.to_string()),
                    _ => None,
                })
                .collect())
            .unwrap_or_default();

        Ok((expiration, names))
    }
}
