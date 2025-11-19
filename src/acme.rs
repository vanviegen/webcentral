use anyhow::{Context, Result};
use instant_acme::{
    Account, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
};
use rcgen::CertificateParams;
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

        let account_path = self.config_dir.join("account.json");

        // Try to load existing account
        if account_path.exists() {
            if let Ok(data) = fs::read_to_string(&account_path) {
                if let Ok(credentials) = serde_json::from_str(&data) {
                    let account = Account::from_credentials(credentials)
                        .await
                        .context("Failed to load ACME account")?;
                    *account_lock = Some(account.clone());
                    return Ok(account);
                }
            }
        }

        // Create new account
        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", self.email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            &self.acme_url,
            None,
        )
        .await
        .context("Failed to create ACME account")?;

        // Save account credentials
        let data = serde_json::to_string(&credentials)?;
        fs::write(&account_path, data)?;

        *account_lock = Some(account.clone());
        Ok(account)
    }

    pub async fn acquire_certificate(&self, domain: &str) -> Result<()> {
        println!("Acquiring certificate for {}", domain);
        let start = std::time::Instant::now();

        let account = self.get_or_create_account().await?;

        // Create new order
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(domain.to_string())],
            })
            .await
            .context("Failed to create new order")?;

        // Get authorizations
        let authorizations = order.authorizations().await?;

        for authz in &authorizations {
            // Find HTTP-01 challenge
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .context("No HTTP-01 challenge found")?;

            let token = challenge.token.as_str();
            let key_auth = order.key_authorization(challenge).as_str().to_string();

            // Store challenge for HTTP-01 server to serve
            {
                let mut challenges = self.challenges.write().await;
                challenges.insert(token.to_string(), (token.to_string(), key_auth.clone()));
            }

            // Tell ACME server we're ready
            order.set_challenge_ready(&challenge.url).await?;
        }

        // Poll for order status
        let mut tries = 0;
        let mut delay = std::time::Duration::from_millis(500);
        let state = loop {
            tokio::time::sleep(delay).await;
            let state = order.refresh().await?;

            if let OrderStatus::Ready | OrderStatus::Invalid | OrderStatus::Valid = state.status {
                break state;
            }

            delay = std::cmp::min(delay * 2, std::time::Duration::from_secs(5));
            tries += 1;
            if tries > 20 {
                anyhow::bail!("Order processing timeout");
            }
        };

        if state.status == OrderStatus::Invalid {
            anyhow::bail!("Order validation failed");
        }

        // Clear challenges
        {
            let mut challenges = self.challenges.write().await;
            challenges.clear();
        }

        // Generate key pair and CSR
        let key_pair = rcgen::KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![domain.to_string()])?;
        let csr = params.serialize_request(&key_pair)?;
        let csr_der = csr.der();

        // Finalize order
        order.finalize(csr_der).await?;

        // Poll for certificate
        let cert_chain_pem = loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            match order.certificate().await? {
                Some(cert_chain) => break cert_chain,
                None => {
                    order.refresh().await?;
                }
            }
        };

        // Save certificate and key
        let cert_path = self.config_dir.join("certs").join(format!("{}.pem", domain));
        let key_path = self.config_dir.join("keys").join(format!("{}.pem", domain));

        fs::write(&cert_path, &cert_chain_pem)?;
        fs::write(&key_path, key_pair.serialize_pem())?;

        println!("  {}: Certificate acquired (took {:?})", domain, start.elapsed());
        Ok(())
    }

    pub fn get_certificate(&self, domain: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let cert_path = self.config_dir.join("certs").join(format!("{}.pem", domain));
        let key_path = self.config_dir.join("keys").join(format!("{}.pem", domain));

        if !cert_path.exists() || !key_path.exists() {
            anyhow::bail!("Certificate not found for domain: {}", domain);
        }

        // Load certificate chain
        let cert_data = fs::read(&cert_path)?;
        let certs = rustls_pemfile::certs(&mut &cert_data[..])
            .collect::<Result<Vec<_>, _>>()?;

        // Load private key
        let key_data = fs::read(&key_path)?;
        let key = rustls_pemfile::private_key(&mut &key_data[..])?
            .context("No private key found")?;

        Ok((certs, key))
    }

    pub fn has_certificate(&self, domain: &str) -> bool {
        let cert_path = self.config_dir.join("certs").join(format!("{}.pem", domain));
        let key_path = self.config_dir.join("keys").join(format!("{}.pem", domain));
        cert_path.exists() && key_path.exists()
    }

    pub async fn get_challenge(&self, token: &str) -> Option<String> {
        let challenges = self.challenges.read().await;
        challenges.get(token).map(|(_, key_auth)| key_auth.clone())
    }
}
