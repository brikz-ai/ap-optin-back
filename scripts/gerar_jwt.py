"""Emite um JWT RS256 de HOMOLOG aceito por shared/jwt_auth.py (iss=brikz-iam, claim financiador_id).

    python scripts/gerar_jwt.py --chave keys/homolog/jwt_private.pem --financiador 12345678000199 --horas 24

A chave é a LOCAL de homolog (scripts/gerar_chaves_jwt.py), cuja pública vai no
segredo IAM_JWT_PUBLIC_KEY — não é a chave do IAM real. Os backends AP só aceitam
esses tokens com IAM_JWT_ACEITAR_CHAVE_HOMOLOG=true e ENVIRONMENT != production.
O token sai com type=access e sub, como o access token do IAM: jwt_auth recusa
token sem sub ou com type diferente de "access" (ex.: refresh).
"""
import argparse
import time
from pathlib import Path

import jwt as pyjwt


def gerar_token(chave_privada: Path, financiador_id: str, horas: int = 24, sub: str = "dev-user") -> str:
    agora = int(time.time())
    return pyjwt.encode(
        {"iss": "brikz-iam", "type": "access", "sub": sub, "iat": agora, "exp": agora + horas * 3600, "financiador_id": financiador_id},
        Path(chave_privada).read_text(),
        algorithm="RS256",
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--chave", required=True)
    p.add_argument("--financiador", required=True)
    p.add_argument("--horas", type=int, default=24)
    p.add_argument("--sub", default="dev-user")
    a = p.parse_args()
    print(gerar_token(Path(a.chave), a.financiador, a.horas, a.sub))
