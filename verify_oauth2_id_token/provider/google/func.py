from .model import GoogleOAuth2JWK


def google_check_algorithm(key: GoogleOAuth2JWK, algorithm: str) -> bool:
    return key.alg == algorithm
