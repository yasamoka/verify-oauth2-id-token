from datetime import datetime
from typing import Literal

from pydantic.networks import EmailStr, HttpUrl

from ..common.model import (
    OAuth2IDTokenBase,
    OAuth2JWKBase,
    OAuth2JWKS,
    OAuth2JWTHeaderBase,
    OAuth2OpenIDConfigurationBase,
)


class GoogleOAuth2OpenIDConfiguration(OAuth2OpenIDConfigurationBase):
    code_challenge_methods_supported: list[str]
    grant_types_supported: list[str]
    issuer: Literal["https://accounts.google.com"]
    revocation_endpoint: HttpUrl


class GoogleOAuth2IDToken(OAuth2IDTokenBase):
    azp: str | None
    email: EmailStr
    email_verified: bool
    family_name: str
    given_name: str
    iat: datetime
    iss: Literal["accounts.google.com"] | Literal["https://accounts.google.com"]
    jti: str
    picture: HttpUrl


class GoogleOAuth2JWK(OAuth2JWKBase):
    alg: str
    use: str


class GoogleOAuth2JWKS(OAuth2JWKS[GoogleOAuth2JWK]):
    keys: list[GoogleOAuth2JWK]


class GoogleOAuth2JWTHeader(OAuth2JWTHeaderBase):
    pass
