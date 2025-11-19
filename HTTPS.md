# HTTPS/TLS Setup Guide

## Quick Start

Enable HTTPS with automatic certificate acquisition:

```bash
# Root user (recommended for ports 80/443)
sudo ./webcentral --email admin@example.com --https 443 --http 80

# Non-root user (requires port forwarding)
./webcentral --email admin@example.com --https 8443 --http 8080
```

## Requirements

1. **Valid domain name(s)** pointing to your server's public IP
2. **Port 80 accessible** from the internet (for HTTP-01 challenges)
3. **Email address** for LetsEncrypt registration (required by ACME)

## How It Works

### Initial Certificate Acquisition

When webcentral starts with HTTPS enabled:

1. **Scans project directories** to discover domains (e.g., `example.com/`, `myapp.net/`)
2. **Checks for existing certificates** in `<config>/certs/`
3. **Requests new certificates** for domains without them
4. **Watches for new domains** and acquires certificates automatically

### ACME Protocol Flow

For each domain:

1. **Account Registration**: Creates/loads ACME account (one-time)
2. **Order Creation**: Requests certificate from LetsEncrypt
3. **HTTP-01 Challenge**:
   - LetsEncrypt provides a challenge token
   - Webcentral serves response at `http://domain/.well-known/acme-challenge/{token}`
   - LetsEncrypt validates from port 80
4. **CSR Generation**: Creates Certificate Signing Request with domain
5. **Finalization**: Submits CSR to LetsEncrypt
6. **Certificate Download**: Polls and saves certificate + private key
7. **TLS Ready**: Certificate available for HTTPS connections

### Runtime Certificate Selection

For each HTTPS connection:

1. **TLS Handshake**: Client connects and requests domain via SNI
2. **Certificate Lookup**: CertResolver loads cert for requested domain
3. **Key Loading**: Private key loaded from disk
4. **Connection**: TLS handshake completes, HTTP request handled

## Directory Structure

```
<config>/                    # Default: /var/lib/webcentral (root) or ~/.webcentral
├── account.json            # ACME account credentials (persisted)
├── bindings.json           # Domain → directory cache
├── certs/
│   ├── example.com.pem    # Certificate chain for example.com
│   └── myapp.net.pem      # Certificate chain for myapp.net
└── keys/
    ├── example.com.pem    # Private key for example.com
    └── myapp.net.pem      # Private key for myapp.net
```

## Configuration Options

```bash
# Required for HTTPS
--email EMAIL                # Email for LetsEncrypt registration
--https PORT                 # HTTPS port (default: 443, 0 to disable)

# Optional
--http PORT                  # HTTP port (default: 80, 0 to disable)
--config PATH                # Config directory (default: /var/lib/webcentral or ~/.webcentral)
--acme-url URL               # ACME endpoint (default: LetsEncrypt production)
--redirect-http              # Redirect HTTP to HTTPS (default: auto if both enabled)
```

## Common Scenarios

### Production Setup (Root)

```bash
sudo ./webcentral \
  --email admin@example.com \
  --https 443 \
  --http 80 \
  --projects "/home/*/webcentral-projects"
```

### Development (Non-Root)

```bash
# Use high ports and port forwarding
./webcentral \
  --email dev@example.com \
  --https 8443 \
  --http 8080

# Then forward with iptables:
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```

### HTTP-Only (No HTTPS)

```bash
./webcentral --http 80 --https 0
```

### HTTPS-Only (After Certificates Acquired)

```bash
# First run: Acquire certificates
./webcentral --email admin@example.com --https 443 --http 80

# Subsequent runs: HTTPS only
./webcentral --email admin@example.com --https 443 --http 0
```

## Troubleshooting

### Certificate Acquisition Fails

**Check domain DNS:**
```bash
dig +short example.com
# Should return your server's public IP
```

**Check port 80 accessibility:**
```bash
curl http://example.com/.well-known/acme-challenge/test
# Should connect (404 is OK, connection refused is not)
```

**Check logs:**
```bash
# Webcentral prints certificate acquisition progress
./webcentral --email ... --https 443 --http 80

# Look for:
# "Acquiring certificate for example.com"
# "Certificate acquired (took 5s)"
```

### TLS Handshake Errors

**Check certificate exists:**
```bash
ls -la ~/.webcentral/certs/example.com.pem
ls -la ~/.webcentral/keys/example.com.pem
```

**Test TLS:**
```bash
openssl s_client -connect example.com:443 -servername example.com
```

### Port Permission Issues

Non-root users can't bind ports <1024:

```bash
# Option 1: Use setcap (persistent)
sudo setcap 'cap_net_bind_service=+ep' ./webcentral

# Option 2: Use authbind
sudo authbind ./webcentral --https 443 --http 80

# Option 3: Use high ports + port forwarding (see above)
```

## Security Notes

1. **Private keys never leave disk** except during TLS handshake
2. **ACME account stored encrypted** by instant-acme library
3. **Certificates are public** (they're sent to clients)
4. **HTTP-01 challenges are public** (required by ACME protocol)
5. **Rate limits apply**: LetsEncrypt allows 50 certs/week per domain

## Certificate Renewal

**Current Status**: Manual renewal required (restart webcentral)

**How to renew:**

1. **Delete expired certificates:**
   ```bash
   rm ~/.webcentral/certs/example.com.pem
   rm ~/.webcentral/keys/example.com.pem
   ```

2. **Restart webcentral:**
   ```bash
   sudo systemctl restart webcentral
   # or
   ./webcentral --email ... --https 443 --http 80
   ```

**Automatic renewal** (planned for future release):
- Monitor certificate expiration
- Request renewal 30 days before expiry
- Hot-reload certificates without restart

## Staging Environment

Test with LetsEncrypt staging to avoid rate limits:

```bash
./webcentral \
  --email test@example.com \
  --https 443 \
  --http 80 \
  --acme-url "https://acme-staging-v02.api.letsencrypt.org/directory"
```

**Note**: Staging certificates are not trusted by browsers (self-signed root).

## Multiple Domains

SNI automatically handles multiple domains:

```bash
# Directory structure:
~/webcentral-projects/
├── example.com/        # Cert acquired for example.com
├── myapp.net/          # Cert acquired for myapp.net
└── blog.example.com/   # Cert acquired for blog.example.com

# Single command serves all domains on HTTPS:
./webcentral --email admin@example.com --https 443 --http 80
```

Each domain gets its own certificate automatically.

## Limitations

- ❌ **Wildcard certificates**: Not supported (requires DNS-01 challenge)
- ❌ **Certificate renewal**: Manual (delete cert + restart)
- ❌ **Certificate revocation**: Not implemented
- ✅ **Multi-domain**: Fully supported via SNI
- ✅ **Certificate caching**: Reused across restarts
- ✅ **Concurrent acquisition**: Multiple domains acquired in parallel
