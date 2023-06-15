from base64 import urlsafe_b64decode
from datetime import datetime
from typing import Callable, Type, TypeVar

from Crypto.PublicKey import RSA
import jwt
from pydantic import ValidationError
from requests_cache import CachedSession

from ..exception import INTEGRITY_CHECK_FAILED_ERROR
from ..model import (
    OAuth2IDTokenBase,
    OAuth2JWKS,
    OAuth2JWKType,
    OAuth2JWTHeaderBase,
    OAuth2OpenIDConfigurationBase,
)


OpenIDConfigurationModelType = TypeVar(
    "OpenIDConfigurationModelType", bound=OAuth2OpenIDConfigurationBase
)
OAuth2JWTHeaderModelType = TypeVar(
    "OAuth2JWTHeaderModelType", bound=OAuth2JWTHeaderBase
)
OAuth2IDTokenModelType = TypeVar("OAuth2IDTokenModelType", bound=OAuth2IDTokenBase)


def get_openid_configuration(
    login_provider_url: str,
    session: CachedSession,
    Model: Type[OpenIDConfigurationModelType],
) -> OpenIDConfigurationModelType:
    openid_configuration_url = (
        f"https://{login_provider_url}/.well-known/openid-configuration"
    )
    openid_configuration_response = (
        session.get(  # pyright: ignore[reportUnknownMemberType]
            openid_configuration_url
        )
    )
    openid_configuration_dict = openid_configuration_response.json()
    openid_configuration = Model.model_validate(openid_configuration_dict)
    return openid_configuration


def get_jwks(
    openid_configuration: OAuth2OpenIDConfigurationBase,
    session: CachedSession,
    Model: Type[OAuth2JWKType],
) -> OAuth2JWKS[OAuth2JWKType]:
    jwks_uri = str(openid_configuration.jwks_uri)
    jwks_response = session.get(jwks_uri)  # pyright: ignore[reportUnknownMemberType]
    jwks_json = jwks_response.json()
    jwks = OAuth2JWKS[Model].model_validate(jwks_json)
    return jwks


def get_unverified_jwt_header(
    id_token: str, Model: Type[OAuth2JWTHeaderModelType]
) -> OAuth2JWTHeaderModelType:
    unverified_jwt_header_dict = jwt.get_unverified_header(id_token)
    try:
        unverified_jwt_header = Model.model_validate(unverified_jwt_header_dict)
        return unverified_jwt_header
    except ValidationError:
        raise INTEGRITY_CHECK_FAILED_ERROR


def get_pem_key(
    jwks: OAuth2JWKS[OAuth2JWKType],
    unverified_jwt_header: OAuth2JWTHeaderBase,
    check_algorithm: Callable[[OAuth2JWKType, str], bool],
) -> bytes:
    for key in jwks.keys:
        if key.kid == unverified_jwt_header.kid and check_algorithm(
            key, unverified_jwt_header.alg
        ):
            modulus = int.from_bytes(urlsafe_b64decode(key.n + "=="), byteorder="big")
            exponent = int.from_bytes(urlsafe_b64decode(key.e + "=="), byteorder="big")
            rsa_key = RSA.construct((modulus, exponent))
            pem_key = rsa_key.export_key("PEM")
            return pem_key
    else:
        raise INTEGRITY_CHECK_FAILED_ERROR


def decode_id_token(
    client_id: str,
    id_token: str,
    unverified_jwt_header: OAuth2JWTHeaderBase,
    pem_key: bytes,
    Model: Type[OAuth2IDTokenModelType],
) -> OAuth2IDTokenModelType:
    try:
        decoded_jwt_dict = jwt.decode(
            id_token,
            pem_key,
            audience=client_id,
            algorithms=[unverified_jwt_header.alg],
        )
        decoded_jwt = Model.model_validate(decoded_jwt_dict)
        return decoded_jwt
    except Exception:
        raise INTEGRITY_CHECK_FAILED_ERROR


def verify_id_token(client_id: str, id_token: OAuth2IDTokenBase) -> None:
    if not (id_token.aud == client_id and id_token.exp > datetime.utcnow()):
        raise INTEGRITY_CHECK_FAILED_ERROR
