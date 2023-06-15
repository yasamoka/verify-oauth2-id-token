from datetime import datetime
from typing import Generic, Literal, TypeVar

from pydantic.main import BaseModel
from pydantic.networks import HttpUrl


class OAuth2OpenIDConfigurationBase(BaseModel):
    authorization_endpoint: HttpUrl
    claims_supported: list[str]
    device_authorization_endpoint: HttpUrl
    id_token_signing_alg_values_supported: list[str]
    jwks_uri: HttpUrl
    response_types_supported: list[str]
    scopes_supported: list[str]
    subject_types_supported: list[str]
    token_endpoint: HttpUrl
    token_endpoint_auth_methods_supported: list[str]
    userinfo_endpoint: HttpUrl


class OAuth2IDTokenBase(BaseModel):
    aud: str
    exp: datetime
    name: str
    nbf: datetime
    sub: str


class OAuth2JWKBase(BaseModel):
    e: str
    kid: str
    kty: str
    n: str


OAuth2JWKType = TypeVar("OAuth2JWKType", bound=OAuth2JWKBase)


class OAuth2JWKS(BaseModel, Generic[OAuth2JWKType]):
    keys: list[OAuth2JWKType]


class OAuth2JWTHeaderBase(BaseModel):
    alg: str
    kid: str
    typ: Literal["JWT"]
