from .model import MicrosoftOAuth2JWK


def microsoft_check_algorithm(key: MicrosoftOAuth2JWK, algorithm: str) -> bool:
    return key.kty == "RSA" and algorithm == "RS256"
