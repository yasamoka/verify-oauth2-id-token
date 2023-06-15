from typing import Literal

from pydantic.class_validators import validator
from pydantic.networks import HttpUrl

from ..common.model import (
    OAuth2IDTokenBase,
    OAuth2JWKBase,
    OAuth2JWKS,
    OAuth2JWTHeaderBase,
    OAuth2OpenIDConfigurationBase,
)


class MicrosoftOAuth2OpenIDConfiguration(OAuth2OpenIDConfigurationBase):
    cloud_graph_host_name: str
    cloud_instance_name: str
    end_session_endpoint: HttpUrl
    frontchannel_logout_supported: bool
    http_logout_supported: bool
    issuer: Literal["https://login.microsoftonline.com/{tenantid}/v2.0"]
    kerberos_endpoint: HttpUrl
    msgraph_host: str
    rbac_url: HttpUrl
    request_uri_parameter_supported: bool
    response_modes_supported: list[str]
    tenant_region_scope: str | None


class MicrosoftOAuth2IDToken(OAuth2IDTokenBase):
    aio: str
    iss: str
    nonce: str
    oid: str
    preferred_username: str
    rh: str
    tid: str
    uti: str
    ver: str

    @validator("iss")
    def validate_iss(cls, v: str):
        assert v.startswith("https://login.microsoftonline.com")
        return v


class MicrosoftOAuth2JWK(OAuth2JWKBase):
    pass


class MicrosoftOAuth2JWKS(OAuth2JWKS[MicrosoftOAuth2JWK]):
    keys: list[MicrosoftOAuth2JWK]


class MicrosoftOAuth2JWTHeader(OAuth2JWTHeaderBase):
    pass
