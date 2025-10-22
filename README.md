# Discourse Connect <-> OIDC Gateway.

A secure authentication bridge between Discourse Connect and OIDC providers, implemented in Python with FastAPI.

## Overview

This service acts as a gateway that allows systemsworld.club using Discourse Connect (formerly SSO) to authenticate users via any OIDC-compliant identity provider (like ORY Hydra, Auth0, Keycloak, etc.).

## Features

- **Secure Authentication Flow**: Two-step OAuth2/OIDC authentication with proper validation
- **JWT Token Validation**: Uses JWKS for secure token verification
- **HMAC-SHA256 Signatures**: Validates all requests from and to Discourse
- **Replay Attack Prevention**: Nonce validation ensures requests can't be replayed
- **Production Ready**: Docker container with health checks and Nomad deployment config
- **Auto-redirect UI**: User-friendly HTML interface with automatic redirects

## Architecture

```
┌──────────┐      ┌─────────────┐      ┌──────────────┐
│   Club   │──1──>│   Gateway   │──2──>│ OIDC Provider│
│          │      │ (This App)  │      │     (ORY)    │
└──────────┘      └─────────────┘      └──────────────┘
        ^                      │                     │
        │                      │                     │
        └──────────5───────────┘<────────3,4─────────┘

Flow:
1. Club sends SSO request with signature
2. Gateway validates and redirects to OIDC provider
3. User authenticates with OIDC provider
4. OIDC provider redirects back with authorization code
5. Gateway exchanges code for tokens, validates JWT, sends user data to club
```

## Installation

### Requirements

- Python 3.11+
- Docker (for containerized deployment)
- Nomad + Consul (for production deployment)

### Local Setup

```bash
# Clone the repository
git clone https://github.com/aisystant/auth.systemsworld.club.git
cd auth.systemsworld.club

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DISCOURSE_CONNECT_SECRET="your-discourse-secret"
export OIDC_CLIENT_ID="your-oidc-client-id"
export OIDC_CLIENT_SECRET="your-oidc-client-secret"
export OIDC_ISSUER="https://your-oidc-provider.com"

# Run the application
python main.py
```

The server will start on `http://0.0.0.0:8000`

### Docker Setup

```bash
# Build the image
docker build -t auth-gateway:latest .

# Run with environment variables
docker run -p 8000:8000 \
  -e DISCOURSE_CONNECT_SECRET="your-secret" \
  -e OIDC_CLIENT_ID="your-client-id" \
  -e OIDC_CLIENT_SECRET="your-client-secret" \
  -e OIDC_ISSUER="https://your-oidc-provider" \
  auth-gateway:latest
```

## Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DISCOURSE_CONNECT_SECRET` | Shared secret configured in club | `your-secret-key` |
| `OIDC_CLIENT_ID` | OAuth2 client ID from your OIDC provider | `abc123...` |
| `OIDC_CLIENT_SECRET` | OAuth2 client secret from your OIDC provider | `secret123...` |
| `OIDC_ISSUER` | Base URL of your OIDC provider | `https://auth.system-school.club` |

### Discourse Configuration

1. Go to Admin → Settings → Login at systemsworld.club
2. Enable "enable discourse connect"
3. Set "discourse connect url" to: `https://auth.systemsworld.club/`
4. Set "discourse connect secret" to match your `DISCOURSE_CONNECT_SECRET`
5. Configure "discourse connect overrides" as needed

### OIDC Provider Configuration

Configure your OIDC provider with:
- **Redirect URI**: `https://auth.systemsworld.club/` (or your deployment URL)
- **Scopes**: `openid email profile`
- **Response Type**: `code`
- **Grant Type**: `authorization_code`

## How It Works

### Step 1: Initial Request from Club

1. User clicks "Log In" on systemsworld.club
2. Club generates a signed SSO payload and redirects to gateway
3. Gateway validates the HMAC-SHA256 signature
4. Gateway extracts the nonce and redirects user to OIDC provider

### Step 2: OIDC Authentication

1. User authenticates with OIDC provider (ORY Hydra)
2. OIDC provider redirects back with authorization code
3. Gateway exchanges code for ID token
4. Gateway validates JWT signature using JWKS
5. Gateway verifies nonce to prevent replay attacks

### Step 3: Return to Club

1. Gateway extracts user info from JWT (email, username, name)
2. Gateway creates signed SSO response for club
3. Gateway redirects user back to systemsworld.club
4. Club validates signature and logs user in

## Security Features

- **HMAC-SHA256 Signature Verification**: All requests validated with shared secret
- **JWT Signature Validation**: ID tokens verified using JWKS from OIDC provider
- **Nonce Verification**: Prevents replay attacks by matching nonces
- **Audience and Issuer Validation**: Ensures tokens are from expected source
- **Non-root Container**: Docker image runs as unprivileged user
- **Health Checks**: Monitors application availability

## API Endpoints

### `GET /`

Main endpoint that handles both steps of the authentication flow.

**Initial SSO Request** (from club):
- Query params: `sso` (base64 payload), `sig` (HMAC signature)
- Response: HTML with redirect to OIDC provider

**OIDC Callback** (from OIDC provider):
- Query params: `code` (authorization code), `state` (contains original SSO data)
- Response: HTTP 302 redirect back to club with signed user data

## Development

### Running Tests

```bash
# Install dev dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest
```

### Project Structure

```
.
├── main.py                 # FastAPI application
├── requirements.txt        # Python dependencies
├── Dockerfile             # Container build config
├── .dockerignore          # Docker build exclusions
├── auth-gateway.nomad     # Nomad job definition
├── README.md              # This file
└── DEPLOYMENT.md          # Deployment guide
```

## Troubleshooting

### "Invalid signature" error

- Verify `DISCOURSE_CONNECT_SECRET` matches in both club and gateway
- Check that the secret doesn't have extra whitespace

### "Failed to fetch token" error

- Verify `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` are correct
- Check that redirect URI is configured in OIDC provider
- Ensure `OIDC_ISSUER` URL is correct (no trailing slash)

### "Invalid id_token signature or claims" error

- Verify `OIDC_ISSUER` matches the issuer in JWT claims
- Check that `OIDC_CLIENT_ID` matches the audience in JWT
- Ensure JWKS endpoint is accessible: `{OIDC_ISSUER}/.well-known/jwks.json`

### "Nonce mismatch" error

- This indicates a potential replay attack or timing issue
- Verify system clocks are synchronized
- Check for proxy/load balancer issues

## Dependencies

- **FastAPI**: Modern, fast web framework for building APIs
- **Uvicorn**: Lightning-fast ASGI server
- **httpx**: Async HTTP client for OIDC token exchange
- **PyJWT**: JWT validation with cryptographic signature verification

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourusername/auth.systemsworld.club/issues
- Documentation: See [DEPLOYMENT.md](DEPLOYMENT.md) for deployment help
