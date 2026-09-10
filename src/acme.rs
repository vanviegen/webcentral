use anyhow::{Context, Result};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// The ACME account as it is kept on disk. The directory it was created on is stored beside it,
/// since credentials for one server say nothing on another - staging and production are different
/// accounts.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredAccount {
    directory: String,
    /// The contact the account was registered with, so that a changed `--email` can be noticed
    #[serde(default)]
    email: String,
    credentials: instant_acme::AccountCredentials,
}

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

    /// Where the ACME account's key is kept between runs.
    fn account_path(&self) -> PathBuf {
        self.config_dir.join("account.json")
    }

    /// The stored account, if there is one for the directory we are ordering from. A file we
    /// cannot use is reported and then ignored - a new account is one round trip, while refusing
    /// to serve HTTPS over it would not get anybody their certificate.
    fn stored_account(&self) -> Option<StoredAccount> {
        let path = self.account_path();
        let data = fs::read(&path).ok()?;
        match serde_json::from_slice::<StoredAccount>(&data) {
            Ok(stored) if stored.directory == self.acme_url => Some(stored),
            // Switching between staging and production is a different account, not a broken file
            Ok(_) => None,
            Err(e) => {
                eprintln!("ERROR: ignoring unreadable ACME account in {}: {}", path.display(), e);
                None
            }
        }
    }

    /// The ACME account, restored from disk or created and saved.
    ///
    /// Keeping it matters beyond saving a round trip: a `CAA` record can name the account allowed
    /// to issue for a domain (`accounturi=`), and Let's Encrypt counts new accounts per IP address
    /// - both of which a webcentral that made a fresh account on every start would run into.
    async fn get_or_create_account(&self) -> Result<Account> {
        let mut account_lock = self.account.write().await;

        if let Some(ref account) = *account_lock {
            return Ok(account.clone());
        }

        if let Some(stored) = self.stored_account() {
            let was = stored.email;
            match Account::builder()?.from_credentials(stored.credentials).await {
                Ok(account) => {
                    println!("Using ACME account {}", account.id());
                    // The contact is settled when the account is registered, so an account kept
                    // between runs is the only thing that can be holding a `--email` since changed
                    if was != self.email {
                        self.update_contact(&account).await;
                    }
                    *account_lock = Some(account.clone());
                    return Ok(account);
                }
                // The key is no longer one the server knows, so there is nothing to keep
                Err(e) => eprintln!("ERROR: stored ACME account is unusable, making a new one: {}", e),
            }
        }

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

        let (account, credentials) = match result {
            Ok(acc) => acc,
            Err(e) => {
                eprintln!("Failed to create ACME account ({}): {:?}", self.email, e);
                return Err(e.into());
            }
        };

        let stored = StoredAccount {
            directory: self.acme_url.clone(),
            email: self.email.clone(),
            credentials,
        };
        if let Err(e) = self.save_account(&stored) {
            // Worth serving HTTPS with an account we couldn't save, but every restart will make
            // another one, which is what a `CAA` accounturi and Let's Encrypt's rate limits notice
            eprintln!("ERROR: could not save the ACME account to {}: {}", self.account_path().display(), e);
        }
        println!("Created ACME account {}", account.id());
        *account_lock = Some(account.clone());
        Ok(account)
    }

    /// Tell the CA about a `--email` that has changed since the account was registered, and
    /// remember that we did. Not worth failing a certificate over: the contact is where the CA
    /// writes to about the account, not part of issuing.
    async fn update_contact(&self, account: &Account) {
        let contact = format!("mailto:{}", self.email);
        if let Err(e) = account.update_contacts(&[contact.as_str()]).await {
            eprintln!("ERROR: could not tell the ACME server the new contact address {}: {}", self.email, e);
            return;
        }
        // Read again rather than keep a copy: the credentials went into the account itself
        if let Some(mut stored) = self.stored_account() {
            stored.email = self.email.clone();
            if let Err(e) = self.save_account(&stored) {
                eprintln!("ERROR: could not save the ACME account to {}: {}", self.account_path().display(), e);
            }
        }
        println!("ACME account contact is now {}", self.email);
    }

    /// Write the account key readable only by the user webcentral runs as.
    fn save_account(&self, stored: &StoredAccount) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(self.account_path())?;
        file.write_all(&serde_json::to_vec(stored)?)?;
        Ok(())
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

    /// Why the ACME server would not authorize an order: what it recorded against each identifier
    /// it refused.
    ///
    /// The order itself carries no reason - a failed challenge's error lives on its authorization,
    /// which has to be read again, since what we read while setting the challenges up was still
    /// pending.
    async fn validation_problem(order: &mut instant_acme::Order, account: &str) -> String {
        let mut problems = Vec::new();
        // A refusal that is about the name rather than about reaching it, and so is answered in
        // DNS rather than by anything webcentral can retry
        let mut caa = false;
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = match result {
                Ok(authz) => authz,
                Err(e) => {
                    problems.push(format!("could not read an authorization: {}", e));
                    continue;
                }
            };
            if let Err(e) = authz.refresh().await {
                problems.push(format!("could not re-read an authorization: {}", e));
                continue;
            }
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }

            let name = authz.identifier().to_string();
            match authz.challenges.iter().find_map(|c| c.error.as_ref()) {
                Some(problem) => {
                    caa |= problem.r#type.as_deref().is_some_and(|t| t.ends_with(":caa"));
                    problems.push(format!("{} ({})", name, problem))
                }
                // Not valid and blaming no challenge: expired, revoked or deactivated, where the
                // status is the whole story
                None => problems.push(format!("{} (authorization is {:?})", name, authz.status)),
            }
        }

        let mut message = match problems.is_empty() {
            true => "the ACME server refused the order without saying which name failed".to_string(),
            false => format!("the ACME server could not validate {}", problems.join("; ")),
        };
        if caa {
            message.push_str(&format!(". A CAA record says which certificate authority may issue \
                for the name, and an `accounturi=` on it says which ACME account - this one is {}", account));
        }
        message
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
                .context("Failed to poll order ready"),
            Err(e) => Err(e),
        };

        // Clean up our challenges, whether or not validation succeeded
        for token in &tokens {
            self.challenges.write().await.remove(token);
        }
        // A rejected order is *returned* as `Invalid` rather than reported as an error: without
        // this, the run would go on to finalize an order the server has already given up on, and
        // fail with the CA complaining about its state rather than about what put it in that state
        if poll_result? != OrderStatus::Ready {
            anyhow::bail!("Validation failed: {}",
                Self::validation_problem(&mut order, account.id()).await);
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
