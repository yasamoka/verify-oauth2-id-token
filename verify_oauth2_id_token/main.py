from typing import Literal, overload

from .provider.google import (
    GoogleOAuth2IDToken,
    verify_google_oauth2_id_token,
)
from .provider.microsoft import (
    MicrosoftOAuth2IDToken,
    verify_microsoft_oauth2_id_token,
)


@overload
def verify_oauth2_id_token(
    client_id: str, id_token: str, login_provider: Literal["google"]
) -> GoogleOAuth2IDToken:
    ...


@overload
def verify_oauth2_id_token(
    client_id: str, id_token: str, login_provider: Literal["microsoft"]
) -> MicrosoftOAuth2IDToken:
    ...


def verify_oauth2_id_token(
    client_id: str,
    id_token: str,
    login_provider: Literal["google"] | Literal["microsoft"],
) -> GoogleOAuth2IDToken | MicrosoftOAuth2IDToken:
    match login_provider:
        case "google":
            return verify_google_oauth2_id_token(client_id=client_id, id_token=id_token)
        case "microsoft":
            return verify_microsoft_oauth2_id_token(
                client_id=client_id, id_token=id_token
            )
