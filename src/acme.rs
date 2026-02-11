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

    pub async fn acquire_certificate(&self, domain: &str) -> Result<()> {
        println!("Acquiring certificate for {}", domain);

        let account = self.get_or_create_account().await?;

        // Create new order
        let order_result = account
            .new_order(&NewOrder::new(&[Identifier::Dns(domain.to_string())]))
            .await;
            
        let mut order = match order_result {
            Ok(o) => o,
            Err(e) => {
                eprintln!("Failed to create certificate order for {}: {:?}", domain, e);
                return Err(anyhow::anyhow!("Failed to create new ACME order for {}", domain));
            }
        };

        // Get authorizations and store tokens for later cleanup
        let mut authorizations = order.authorizations();
        let mut tokens_to_clean = Vec::new();

        while let Some(result) = authorizations.next().await {
            let mut authz = result.with_context(|| format!("Failed to get authorization for {}", domain))?;

            // Find HTTP-01 challenge
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .with_context(|| format!("No HTTP-01 challenge found for {}", domain))?;

            let token = challenge.token.clone();
            let key_auth = challenge.key_authorization();
            
            // Store challenge for HTTP-01 server to serve
            {
                let mut challenges = self.challenges.write().await;
                challenges.insert(token.clone(), (token.clone(), key_auth.as_str().to_string()));
            }
            
            tokens_to_clean.push(token.clone());
            
            // Tell ACME server we're ready
            challenge.set_ready().await.with_context(|| format!("Failed to set challenge ready for {}", domain))?;
        }

        // Wait for order to be ready (this is when ACME server validates the challenges)
        use instant_acme::RetryPolicy;
        order
            .poll_ready(&RetryPolicy::default())
            .await
            .context("Failed to poll order ready - this usually means the HTTP-01 challenge failed. Check that DNS points to this server and port 80 is accessible.")?;

        // Now clean up only this domain's challenges
        {
            let mut challenges = self.challenges.write().await;
            for token in tokens_to_clean {
                challenges.remove(&token);
            }
        }

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

        // Save certificate and key
        let cert_path = self
            .config_dir
            .join("certs")
            .join(format!("{}.pem", domain));
        let key_path = self.config_dir.join("keys").join(format!("{}.pem", domain));

        fs::write(&cert_path, &cert_chain_pem)?;
        fs::write(&key_path, &private_key_pem)?;

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



    pub async fn get_challenge(&self, token: &str) -> Option<String> {
        let challenges = self.challenges.read().await;
        challenges.get(token).map(|(_, key_auth)| key_auth.clone())
    }

    pub fn get_certificate_expiration(&self, domain: &str) -> Result<std::time::SystemTime> {
        let cert_path = self
            .config_dir
            .join("certs")
            .join(format!("{}.pem", domain));

        if !cert_path.exists() {
            anyhow::bail!("Certificate not found for domain: {}", domain);
        }

        let cert_data = fs::read(&cert_path)?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(&cert_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse PEM: {}", e))?;
        
        let cert = pem.parse_x509()
            .map_err(|e| anyhow::anyhow!("Failed to parse X.509 certificate: {}", e))?;

        // Convert ASN.1 time to SystemTime
        // x509-parser returns ASN1Time, which has a to_datetime() method returning OffsetDateTime
        // We need to convert that to SystemTime
        let expiration = cert.validity().not_after.to_datetime();
        
        // Convert time::OffsetDateTime to std::time::SystemTime
        let system_time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(expiration.unix_timestamp() as u64);
        
        Ok(system_time)
    }
}
