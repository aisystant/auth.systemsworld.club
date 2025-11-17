import os
import json
import hmac
import hashlib
import base64
import re
from urllib.parse import urlencode, parse_qs, urlparse, urljoin
from typing import Optional, Dict, Any

import httpx
from jwt import PyJWKClient, decode as jwt_decode
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI()


# Helper functions
def hmac_sha256_hex(secret: str, message: str) -> str:
    """Generate HMAC-SHA256 signature and return as hex string."""
    return hmac.new(
        secret.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def decode_base64_to_string(base64_string: str) -> str:
    """Decode base64 string to UTF-8 text."""
    return base64.b64decode(base64_string).decode('utf-8')


def encode_string_to_base64(text: str) -> str:
    """Encode UTF-8 text to base64 string."""
    return base64.b64encode(text.encode('utf-8')).decode('utf-8')


def is_valid_email(email: Optional[str]) -> bool:
    """Very small email validity check sufficient for Discourse expectations."""
    if not email or '@' not in email:
        return False
    # basic RFC-like check without being overly strict
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


def sanitize_username(raw_username: Optional[str]) -> str:
    """Normalize username to Discourse-compatible: [a-z0-9_], 3..25 chars."""
    base = (raw_username or '').lower()
    base = re.sub(r"[^a-z0-9_]", "_", base)
    base = re.sub(r"_+", "_", base).strip('_')
    if len(base) < 3:
        base = (base + "_user")[:3]
    return base[:25] or 'user'


@app.get("/")
async def handle_auth(request: Request):
    """Main handler for Discourse Connect <-> OIDC gateway."""
    print("\n" + "="*80)
    print("INCOMING REQUEST")
    print("="*80)
    print(f"URL: {request.url}")
    print(f"Query params: {dict(request.query_params)}")

    # Load environment variables
    discourse_secret = os.getenv('DISCOURSE_CONNECT_SECRET')
    client_id = os.getenv('OIDC_CLIENT_ID')
    client_secret = os.getenv('OIDC_CLIENT_SECRET')
    issuer = os.getenv('OIDC_ISSUER')
    GATEWAY_URL = os.getenv('GATEWAY_URL', 'https://auth.systemsworld.club/')

    print("\n[ENV VARS]")
    print(f"DISCOURSE_CONNECT_SECRET set: {bool(discourse_secret)}")
    print(f"OIDC_CLIENT_ID: {client_id}")
    print(f"OIDC_CLIENT_SECRET set: {bool(client_secret)}")
    print(f"OIDC_ISSUER: {issuer}")
    print(f"GATEWAY_URL: {GATEWAY_URL}")

    if not all([discourse_secret, client_id, client_secret, issuer]):
        print("[ERROR] Missing environment configuration")
        return Response(content='Missing environment configuration', status_code=500)

    # Parse query parameters
    code = request.query_params.get('code')
    state_param = request.query_params.get('state')

    print("\n[QUERY PARAMS]")
    print(f"code: {'***' if code else None}")
    print(f"state: {'***' if state_param else None}")

    # Step 2: Handle OIDC redirect back
    if code and state_param:
        print("\n" + "="*80)
        print("STEP 2: HANDLING OIDC REDIRECT BACK")
        print("="*80)
        try:
            print(f"Attempting to decode state parameter...")
            state_decoded = json.loads(decode_base64_to_string(state_param))
            print(f"State decoded successfully: {state_decoded}")
            sso = state_decoded.get('sso')
            sig = state_decoded.get('sig')
            print(f"Extracted sso: {sso[:50]}..." if sso else "sso: None")
            print(f"Extracted sig: {sig}")
        except Exception as e:
            print(f"[ERROR] Failed to decode state: {e}")
            return Response(content='Invalid state format', status_code=400)

        if not sso or not sig:
            print(f"[ERROR] Missing sso or sig in state - sso: {bool(sso)}, sig: {bool(sig)}")
            return Response(content='Missing sso or sig in state', status_code=400)

        # Validate signature again
        print("\n[SIGNATURE VALIDATION]")
        expected_sig = hmac_sha256_hex(discourse_secret, sso)
        print(f"Expected sig: {expected_sig}")
        print(f"Received sig: {sig.lower()}")
        print(f"Signature valid: {expected_sig == sig.lower()}")
        if expected_sig != sig.lower():
            print("[ERROR] Invalid signature")
            return Response(content='Invalid signature', status_code=403)

        # Exchange code for token
        print("\n[TOKEN EXCHANGE]")
        internal_url = os.getenv('OIDC_INTERNAL_URL')
        if internal_url:
            token_endpoint = internal_url.rstrip('/') + '/oauth2/token'
        else:
            token_endpoint = issuer.rstrip('/') + '/oauth2/token'

        print(f"Token endpoint: {token_endpoint}")
        print(f"Authorization code: ***")
        redirect_uri = f"{GATEWAY_URL.rstrip('/')}{request.url.path}"
        print(f"Redirect URI: {redirect_uri}")

        async with httpx.AsyncClient() as client:
            print("Sending POST request to token endpoint...")
            token_response = await client.post(
                token_endpoint,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'redirect_uri': redirect_uri,
                }
            )

        print(f"Token response status: {token_response.status_code}")
        if token_response.status_code != 200:
            print(f"[ERROR] Token response: {token_response.text}")
            return Response(content='Failed to fetch token', status_code=502)

        token_data = token_response.json()
        print(f"Token data keys: {list(token_data.keys())}")
        id_token = token_data.get('id_token')

        if not id_token:
            print("[ERROR] Missing id_token in token response")
            return Response(content='Missing id_token in token response', status_code=502)

        # Secure JWT validation with PyJWT
        print("\n[JWT VALIDATION]")
        internal_url = os.getenv('OIDC_INTERNAL_URL')
        if internal_url:
            jwks_url = f"{internal_url}/.well-known/jwks.json"
        else:
            jwks_url = f"{issuer}/.well-known/jwks.json"
        print(f"JWKS URL: {jwks_url}")
        jwks_client = PyJWKClient(jwks_url)

        try:
            print("Fetching signing key from JWKS...")
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)
            print(f"Signing key obtained: {signing_key.key_id}")
            print(f"Attempting to decode JWT with audience={client_id}, issuer={issuer}")
            jwt_payload = jwt_decode(
                id_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=client_id,
                issuer=issuer
            )
            print(f"JWT decoded successfully")
            print(f"JWT payload keys: {list(jwt_payload.keys())}")
        except Exception as e:
            print(f"[ERROR] JWT validation failed: {e}")
            return Response(content='Invalid id_token signature or claims', status_code=403)

        # Parse SSO payload
        print("\n[SSO PAYLOAD PARSING]")
        decoded_payload = parse_qs(decode_base64_to_string(sso))
        print(f"Decoded payload keys: {list(decoded_payload.keys())}")
        nonce = decoded_payload.get('nonce', [None])[0]
        return_sso_url = decoded_payload.get('return_sso_url', [None])[0]
        print(f"Nonce from SSO: {nonce}")
        print(f"Return SSO URL: {return_sso_url}")

        if not nonce or not return_sso_url:
            print(f"[ERROR] Invalid SSO payload - nonce: {bool(nonce)}, return_sso_url: {bool(return_sso_url)}")
            return Response(content='Invalid SSO payload', status_code=400)

        # Verify nonce to prevent replay attacks
        print("\n[NONCE VERIFICATION]")
        jwt_nonce = jwt_payload.get('nonce')
        print(f"Nonce from JWT: {jwt_nonce}")
        print(f"Nonce from SSO: {nonce}")
        print(f"Nonce match: {jwt_nonce == nonce}")
        if jwt_nonce != nonce:
            print("[ERROR] Nonce mismatch - possible replay attack")
            return Response(content='Nonce mismatch (possible replay attack)', status_code=403)

        # Extract user information from JWT with safe fallbacks
        print("\n[USER DATA EXTRACTION]")
        sub = jwt_payload.get('sub')
        email_claim = jwt_payload.get('email')
        email_verified_claim = jwt_payload.get('email_verified')

        print(f"sub: {sub}")
        print(f"email_claim: {email_claim}")
        print(f"email_verified_claim: {email_verified_claim}")
        print(f"email valid: {is_valid_email(email_claim)}")

        if is_valid_email(email_claim):
            email = email_claim
            # require_activation = 'false' if (email_verified_claim is True) else 'true'
            require_activation = 'true' if (email_verified_claim is False) else 'false'
            print(f"Using email from JWT: {email}")
        else:
            # Fallback to synthetic email when Hydra does not provide a valid email
            email = f"{sub}@users.systemsworld.club"
            # Activation email недоступен в проде (почта отключена), поэтому не требуем активацию
            require_activation = 'false'
            print(f"Using synthetic email: {email}")

        print(f"require_activation: {require_activation}")

        preferred_username = jwt_payload.get('preferred_username')
        username_guess = preferred_username or (email.split('@')[0] if email else sub)
        username = sanitize_username(username_guess)
        name = jwt_payload.get('name') or username

        print(f"preferred_username: {preferred_username}")
        print(f"username_guess: {username_guess}")
        print(f"sanitized username: {username}")
        print(f"name: {name}")

        user = {
            'external_id': sub,
            'email': email,
            'username': username,
            'name': name,
        }

        print(f"\nFinal user data: {user}")

        # Build outgoing payload for Discourse
        print("\n[DISCOURSE PAYLOAD BUILDING]")
        outgoing_payload = urlencode({
            'nonce': nonce,
            'email': user['email'],
            'external_id': user['external_id'],
            'username': user['username'],
            'name': user['name'],
            'require_activation': require_activation,
        })

        print("Outgoing payload for Discourse:", outgoing_payload)

        base64_payload = encode_string_to_base64(outgoing_payload)
        print(f"Base64 encoded payload: {base64_payload}")

        response_sig = hmac_sha256_hex(discourse_secret, base64_payload)
        print(f"Response signature: {response_sig}")

        # Build redirect URL back to Discourse
        print("\n[REDIRECT URL BUILDING]")
        print(f"Return SSO URL: {return_sso_url}")
        parsed_url = urlparse(return_sso_url)
        query_params = parse_qs(parsed_url.query)
        query_params['sso'] = [base64_payload]
        query_params['sig'] = [response_sig]

        redirect_url = parsed_url._replace(
            query=urlencode(query_params, doseq=True)
        ).geturl()

        print(f"Final redirect URL: {redirect_url}")
        print("\n" + "="*80)
        print("REDIRECTING TO DISCOURSE")
        print("="*80)
        return RedirectResponse(url=redirect_url, status_code=302)

    # Step 1: Initial request from Discourse
    print("\n" + "="*80)
    print("STEP 1: INITIAL REQUEST FROM DISCOURSE")
    print("="*80)
    sso = request.query_params.get('sso')
    sig = request.query_params.get('sig')

    print(f"SSO param: {sso[:50]}..." if sso else "SSO param: None")
    print(f"Sig param: {sig}")

    if not sso or not sig:
        print("[ERROR] Missing sso or sig parameters")
        return Response(content='Missing sso or sig', status_code=400)

    # Validate incoming signature
    print("\n[INCOMING SIGNATURE VALIDATION]")
    expected_sig = hmac_sha256_hex(discourse_secret, sso)
    print(f"Expected sig: {expected_sig}")
    print(f"Received sig: {sig.lower()}")
    print(f"Signature valid: {expected_sig == sig.lower()}")
    if expected_sig != sig.lower():
        print("[ERROR] Invalid signature")
        return Response(content='Invalid signature', status_code=403)

    # Parse SSO payload and extract nonce
    print("\n[SSO PAYLOAD PARSING]")
    decoded_sso = parse_qs(decode_base64_to_string(sso))
    print(f"Decoded SSO keys: {list(decoded_sso.keys())}")
    nonce = decoded_sso.get('nonce', [None])[0]
    print(f"Nonce extracted: {nonce}")

    if not nonce:
        print("[ERROR] Missing nonce in SSO payload")
        return Response(content='Missing nonce in SSO payload', status_code=400)

    # Build state parameter containing original SSO data
    print("\n[BUILDING AUTHORIZATION REQUEST]")
    state = encode_string_to_base64(json.dumps({'sso': sso, 'sig': sig}))
    print(f"State parameter created: {state[:50]}...")

    redirect_uri = f"{GATEWAY_URL.rstrip('/')}{request.url.path}"
    authorization_endpoint = issuer.rstrip('/') + '/oauth2/auth'

    print(f"Redirect URI: {redirect_uri}")
    print(f"Authorization endpoint: {authorization_endpoint}")
    print(f"Nonce: {nonce}")

    # Build authorization URL
    auth_params = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'scope': 'openid email profile',
        'state': state,
        'nonce': nonce,
    }
    auth_url = f"{authorization_endpoint}?{urlencode(auth_params)}"

    print(f"Authorization URL created: {auth_url[:100]}...")
    print("\n" + "="*80)
    print("REDIRECTING TO OIDC PROVIDER")
    print("="*80)

    # Return HTML with auto-redirect
    html_content = f"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Logging in...</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="refresh" content="0; url={auth_url}" />
    <style>
      body {{ font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; background: #f9f9f9; }}
      .box {{ text-align: center; }}
    </style>
  </head>
  <body>
    <div class="box">
      <p>Logging in via Aisystant...</p>
      <p>If you're not redirected, <a href="{auth_url}">click here</a>.</p>
    </div>
    <script>
      setTimeout(() => {{
        window.location.href = {json.dumps(auth_url)};
      }}, 100);
    </script>
  </body>
</html>"""

    return HTMLResponse(content=html_content, status_code=200)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
