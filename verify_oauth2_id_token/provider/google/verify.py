# thanks to https://ncona.com/2015/02/consuming-a-google-id-token-from-a-server/

from requests_cache import CachedSession

from ..common.func import (
    decode_id_token,
    get_jwks,
    get_openid_configuration,
    get_pem_key,
    get_unverified_jwt_header,
    verify_id_token,
)
from .constant import GOOGLE_LOGIN_PROVIDER_URL
from .func import google_check_algorithm
from .model import (
    GoogleOAuth2IDToken,
    GoogleOAuth2JWKS,
    GoogleOAuth2JWTHeader,
    GoogleOAuth2OpenIDConfiguration,
)


def verify_google_oauth2_id_token(id_token: str, client_id: str) -> GoogleOAuth2IDToken:
    session = CachedSession(cache_control=True)

    openid_configuration = get_openid_configuration(
        login_provider_url=GOOGLE_LOGIN_PROVIDER_URL,
        session=session,
        Model=GoogleOAuth2OpenIDConfiguration,
    )
    jwks_json = get_jwks(
        openid_configuration=openid_configuration,
        session=session,
    )
    jwks = GoogleOAuth2JWKS.validate(jwks_json)

    unverified_jwt_header = get_unverified_jwt_header(
        id_token=id_token, Model=GoogleOAuth2JWTHeader
    )
    pem_key = get_pem_key(
        jwks=jwks,
        unverified_jwt_header=unverified_jwt_header,
        check_algorithm=google_check_algorithm,
    )
    decoded_id_token = decode_id_token(
        client_id=client_id,
        id_token=id_token,
        unverified_jwt_header=unverified_jwt_header,
        pem_key=pem_key,
        Model=GoogleOAuth2IDToken,
    )

    verify_id_token(client_id=client_id, id_token=decoded_id_token)

    return decoded_id_token
