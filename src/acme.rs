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
        let (account, _credentials) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", self.email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.acme_url.clone(),
                None,
            )
            .await
            .context("Failed to create ACME account")?;

        *account_lock = Some(account.clone());
        Ok(account)
    }

    pub async fn acquire_certificate(&self, domain: &str) -> Result<()> {
        println!("Acquiring certificate for {}", domain);
        let start = std::time::Instant::now();

        let account = self.get_or_create_account().await?;

        // Create new order
        let mut order = account
            .new_order(&NewOrder::new(&[Identifier::Dns(domain.to_string())]))
            .await
            .context("Failed to create new order")?;

        // Get authorizations
        let mut authorizations = order.authorizations();

        while let Some(result) = authorizations.next().await {
            let mut authz = result?;

            // Find HTTP-01 challenge
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .context("No HTTP-01 challenge found")?;

            let token = &challenge.token;
            let key_auth = challenge.key_authorization();

            // Store challenge for HTTP-01 server to serve
            {
                let mut challenges = self.challenges.write().await;
                challenges.insert(token.to_string(), (token.to_string(), key_auth.as_str().to_string()));
            }

            // Tell ACME server we're ready
            challenge.set_ready().await?;
        }

        // Clear challenges
        {
            let mut challenges = self.challenges.write().await;
            challenges.clear();
        }

        // Wait for order to be ready, then finalize
        use instant_acme::RetryPolicy;
        order.poll_ready(&RetryPolicy::default()).await?;

        // Finalize order - this generates the private key and returns it
        let private_key_pem = order.finalize().await?;

        // Poll for certificate
        let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

        // Save certificate and key
        let cert_path = self
            .config_dir
            .join("certs")
            .join(format!("{}.pem", domain));
        let key_path = self.config_dir.join("keys").join(format!("{}.pem", domain));

        fs::write(&cert_path, &cert_chain_pem)?;
        fs::write(&key_path, &private_key_pem)?;

        println!(
            "  {}: Certificate acquired (took {:?})",
            domain,
            start.elapsed()
        );
        Ok(())
    }

    pub fn get_certificate(
        &self,
        domain: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let cert_path = self
            .config_dir
            .join("certs")
            .join(format!("{}.pem", domain));
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

    pub fn has_certificate(&self, domain: &str) -> bool {
        let cert_path = self
            .config_dir
            .join("certs")
            .join(format!("{}.pem", domain));
        let key_path = self.config_dir.join("keys").join(format!("{}.pem", domain));
        cert_path.exists() && key_path.exists()
    }

    pub async fn get_challenge(&self, token: &str) -> Option<String> {
        let challenges = self.challenges.read().await;
        challenges.get(token).map(|(_, key_auth)| key_auth.clone())
    }
}
