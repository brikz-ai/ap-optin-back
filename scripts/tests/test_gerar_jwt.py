import jwt as pyjwt

from scripts.gerar_chaves_jwt import gerar_par
from scripts.gerar_jwt import gerar_token


def test_token_gerado_valida_com_a_publica_e_carrega_financiador(tmp_path):
    priv, pub = gerar_par(tmp_path)
    token = gerar_token(priv, financiador_id="12345678000199", horas=1)
    claims = pyjwt.decode(token, pub.read_text(), algorithms=["RS256"], issuer="brikz-iam")
    assert claims["financiador_id"] == "12345678000199"
    assert claims["sub"] == "dev-user"
    assert claims["type"] == "access"


def test_token_gerado_passa_no_jwt_auth_com_a_chave_de_homolog_liberada(tmp_path, monkeypatch):
    # Garante que o script continua servindo para homolog depois do
    # endurecimento do jwt_auth (sub obrigatório, type == "access").
    from shared.jwt_auth import validar_bearer_token

    priv, pub = gerar_par(tmp_path)
    monkeypatch.setenv("IAM_JWT_PUBLIC_KEY", pub.read_text())
    monkeypatch.delenv("IAM_JWT_PUBLIC_KEY_BRIKZ_IAM", raising=False)
    monkeypatch.delenv("IAM_JWT_PUBLIC_KEYS", raising=False)
    monkeypatch.setenv("IAM_JWT_ISSUER", "brikz-iam")
    monkeypatch.setenv("IAM_JWT_ACEITAR_CHAVE_HOMOLOG", "true")
    monkeypatch.setenv("ENVIRONMENT", "homolog")
    claims = validar_bearer_token(f"Bearer {gerar_token(priv, financiador_id='12345678000199', horas=1)}")
    assert claims["type"] == "access"
    assert claims["sub"] == "dev-user"
