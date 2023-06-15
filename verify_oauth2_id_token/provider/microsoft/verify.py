from requests_cache import CachedSession

from ..common.func import (
    decode_id_token,
    get_jwks,
    get_openid_configuration,
    get_pem_key,
    get_unverified_jwt_header,
    verify_id_token,
)
from .constant import MICROSOFT_LOGIN_PROVIDER_URL
from .func import microsoft_check_algorithm
from .model import (
    MicrosoftOAuth2IDToken,
    MicrosoftOAuth2JWKS,
    MicrosoftOAuth2JWTHeader,
    MicrosoftOAuth2OpenIDConfiguration,
)


def verify_microsoft_oauth2_id_token(
    id_token: str, client_id: str
) -> MicrosoftOAuth2IDToken:
    session = CachedSession(cache_control=True)

    openid_configuration = get_openid_configuration(
        login_provider_url=MICROSOFT_LOGIN_PROVIDER_URL,
        session=session,
        Model=MicrosoftOAuth2OpenIDConfiguration,
    )
    jwks_json = get_jwks(
        openid_configuration=openid_configuration,
        session=session,
    )
    jwks = MicrosoftOAuth2JWKS.validate(jwks_json)

    unverified_jwt_header = get_unverified_jwt_header(
        id_token=id_token, Model=MicrosoftOAuth2JWTHeader
    )
    pem_key = get_pem_key(
        jwks=jwks,
        unverified_jwt_header=unverified_jwt_header,
        check_algorithm=microsoft_check_algorithm,
    )
    decoded_id_token = decode_id_token(
        client_id=client_id,
        id_token=id_token,
        unverified_jwt_header=unverified_jwt_header,
        pem_key=pem_key,
        Model=MicrosoftOAuth2IDToken,
    )

    verify_id_token(client_id=client_id, id_token=decoded_id_token)

    return decoded_id_token
