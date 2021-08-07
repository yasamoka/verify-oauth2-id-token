# thanks to https://ncona.com/2015/02/consuming-a-google-id-token-from-a-server/

from base64 import urlsafe_b64decode
from enum import Enum

from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from datetime import datetime
import jwt
from pydantic import validate_arguments
from requests_cache import CachedSession


class LoginProvider(str, Enum):
    GOOGLE = 'google'
    MICROSOFT = 'microsoft'


_ALGORITHM_CHECKS = [
    lambda key, algorithm: key['alg'] == algorithm,
    lambda key, algorithm: key['kty'] == 'RSA' and algorithm == 'RS256'
]

_ISS_CHECKS = [
    lambda decoded_jwt, login_provider_url: decoded_jwt['iss'] == login_provider_url or decoded_jwt['iss'] == f'https://{login_provider_url}',
    lambda decoded_jwt, _: decoded_jwt['iss'].startswith('https://login.microsoftonline.com/')
]

LOGIN_PROVIDER_URLS = {
    LoginProvider.GOOGLE: 'accounts.google.com',
    LoginProvider.MICROSOFT: 'login.microsoftonline.com/common/v2.0'
}

ALGORITHM_CHECKS = {
    LoginProvider.GOOGLE: _ALGORITHM_CHECKS[0],
    LoginProvider.MICROSOFT: _ALGORITHM_CHECKS[1]
}

ISS_CHECKS = {
    LoginProvider.GOOGLE: _ISS_CHECKS[0],
    LoginProvider.MICROSOFT: _ISS_CHECKS[1]
}

INTEGRITY_CHECK_FAILED_ERROR = ValueError("ID token integrity check failed")

@validate_arguments
def verify_oauth2_id_token(token_id: str, client_id: str, login_provider: LoginProvider):
    session = CachedSession(cache_control=True)

    login_provider_url = LOGIN_PROVIDER_URLS[login_provider]
    openid_configuration_url = f'https://{login_provider_url}/.well-known/openid-configuration'
    openid_configuration_response = session.get(openid_configuration_url)
    openid_configuration = openid_configuration_response.json()

    jwks_uri = openid_configuration['jwks_uri']
    jwks_response = session.get(jwks_uri)
    jwks = jwks_response.json()

    unverified_jwt_header = jwt.get_unverified_header(token_id)

    try:
        assert unverified_jwt_header['typ'] == 'JWT'
        algorithm = unverified_jwt_header['alg']
    except AssertionError:
        raise INTEGRITY_CHECK_FAILED_ERROR
    except KeyError:
        raise INTEGRITY_CHECK_FAILED_ERROR

    algorithm_check = ALGORITHM_CHECKS[login_provider]
    for key in jwks['keys']:
        if key['kid'] == unverified_jwt_header['kid'] and algorithm_check(key, algorithm):
            modulus, exponent = [
                int.from_bytes(urlsafe_b64decode(key[sub_key] + '=='), byteorder='big')
                for sub_key in ('n', 'e')
            ]
            rsa_key = RSA.construct((modulus, exponent))
            pem_key = rsa_key.export_key('PEM')
            break
    else:
        raise INTEGRITY_CHECK_FAILED_ERROR

    public_key = serialization.load_pem_public_key(pem_key)

    try:
        decoded_jwt = jwt.decode(token_id, public_key, audience=client_id, algorithms=[algorithm])
    except Exception:
        raise INTEGRITY_CHECK_FAILED_ERROR

    iss_check = ISS_CHECKS[login_provider]
    try:
        assert decoded_jwt['aud'] == client_id
        assert iss_check(decoded_jwt, login_provider_url)
        assert decoded_jwt['exp'] > datetime.utcnow().timestamp()
    except AssertionError:
        raise INTEGRITY_CHECK_FAILED_ERROR

    return decoded_jwt
