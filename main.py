import os
import json
import hmac
import hashlib
import base64
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


@app.get("/")
async def handle_auth(request: Request):
    """Main handler for Discourse Connect <-> OIDC gateway."""

    # Load environment variables
    discourse_secret = os.getenv('DISCOURSE_CONNECT_SECRET')
    client_id = os.getenv('OIDC_CLIENT_ID')
    client_secret = os.getenv('OIDC_CLIENT_SECRET')
    issuer = os.getenv('OIDC_ISSUER')
    GATEWAY_URL = os.getenv('GATEWAY_URL', 'https://auth.systemsworld.club/')

    if not all([discourse_secret, client_id, client_secret, issuer]):
        return Response(content='Missing environment configuration', status_code=500)

    # Parse query parameters
    code = request.query_params.get('code')
    state_param = request.query_params.get('state')

    # Step 2: Handle OIDC redirect back
    if code and state_param:
        try:
            state_decoded = json.loads(decode_base64_to_string(state_param))
            sso = state_decoded.get('sso')
            sig = state_decoded.get('sig')
        except Exception:
            return Response(content='Invalid state format', status_code=400)

        if not sso or not sig:
            return Response(content='Missing sso or sig in state', status_code=400)

        # Validate signature again
        expected_sig = hmac_sha256_hex(discourse_secret, sso)
        if expected_sig != sig.lower():
            return Response(content='Invalid signature', status_code=403)

        # Exchange code for token
        token_endpoint = issuer.rstrip('/') + '/oauth2/token'

        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                token_endpoint,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'redirect_uri': f"{GATEWAY_URL}{request.url.path}",
                }
            )

        if token_response.status_code != 200:
            return Response(content='Failed to fetch token', status_code=502)

        token_data = token_response.json()
        id_token = token_data.get('id_token')

        if not id_token:
            return Response(content='Missing id_token in token response', status_code=502)

        # Secure JWT validation with PyJWT
        jwks_url = f"{issuer}/.well-known/jwks.json"
        jwks_client = PyJWKClient(jwks_url)

        try:
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)
            jwt_payload = jwt_decode(
                id_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=client_id,
                issuer=issuer
            )
        except Exception:
            return Response(content='Invalid id_token signature or claims', status_code=403)

        # Parse SSO payload
        decoded_payload = parse_qs(decode_base64_to_string(sso))
        nonce = decoded_payload.get('nonce', [None])[0]
        return_sso_url = decoded_payload.get('return_sso_url', [None])[0]

        if not nonce or not return_sso_url:
            return Response(content='Invalid SSO payload', status_code=400)

        # Verify nonce to prevent replay attacks
        if jwt_payload.get('nonce') != nonce:
            return Response(content='Nonce mismatch (possible replay attack)', status_code=403)

        # Extract user information from JWT
        user = {
            'external_id': jwt_payload.get('sub'),
            'email': jwt_payload.get('email'),
            'username': jwt_payload.get('preferred_username') or jwt_payload.get('email', '').split('@')[0],
            'name': jwt_payload.get('name') or jwt_payload.get('email'),
        }

        # Build outgoing payload for Discourse
        outgoing_payload = urlencode({
            'nonce': nonce,
            'email': user['email'],
            'external_id': user['external_id'],
            'username': user['username'],
            'name': user['name'],
            'require_activation': 'false',
        })

        base64_payload = encode_string_to_base64(outgoing_payload)
        response_sig = hmac_sha256_hex(discourse_secret, base64_payload)

        # Build redirect URL back to Discourse
        parsed_url = urlparse(return_sso_url)
        query_params = parse_qs(parsed_url.query)
        query_params['sso'] = [base64_payload]
        query_params['sig'] = [response_sig]

        redirect_url = parsed_url._replace(
            query=urlencode(query_params, doseq=True)
        ).geturl()

        return RedirectResponse(url=redirect_url, status_code=302)

    # Step 1: Initial request from Discourse
    sso = request.query_params.get('sso')
    sig = request.query_params.get('sig')

    if not sso or not sig:
        return Response(content='Missing sso or sig', status_code=400)

    # Validate incoming signature
    expected_sig = hmac_sha256_hex(discourse_secret, sso)
    if expected_sig != sig.lower():
        return Response(content='Invalid signature', status_code=403)

    # Parse SSO payload and extract nonce
    decoded_sso = parse_qs(decode_base64_to_string(sso))
    nonce = decoded_sso.get('nonce', [None])[0]

    if not nonce:
        return Response(content='Missing nonce in SSO payload', status_code=400)

    # Build state parameter containing original SSO data
    state = encode_string_to_base64(json.dumps({'sso': sso, 'sig': sig}))
    redirect_uri = f"{GATEWAY_URL}{request.url.path}"
    authorization_endpoint = issuer.rstrip('/') + '/oauth2/auth'

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
