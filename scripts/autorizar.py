#!/usr/bin/env python3
"""Autoriza o Noema Analytics a LER o canal do YouTube da Noema.

Guarda o ID, a chave secreta e o token só em /home/sisifo/.env_analytics (chmod 600).
Nunca imprime segredo. Só usa escopos de leitura. Só Python padrão, sem instalar nada.
"""
import base64, getpass, hashlib, json, os, pwd, secrets, sys, urllib.error, urllib.parse, urllib.request

ENV = os.environ.get("NOEMA_ENV", "/home/sisifo/.env_analytics")
REDIRECT = "http://127.0.0.1:8765"
SCOPES = ["https://www.googleapis.com/auth/yt-analytics.readonly", "https://www.googleapis.com/auth/youtube.readonly"]
CANAL = "noema_ia"
AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN = "https://oauth2.googleapis.com/token"
CANAIS = "https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true"
REVOGAR = "https://oauth2.googleapis.com/revoke"


def falha(motivo, proximo):
    sys.exit(f"\nFALHOU: {motivo}\nPróxima ação: {proximo}")


def ler_env():
    if not os.path.exists(ENV):
        return {}
    with open(ENV, encoding="utf-8") as f:
        return dict(linha.rstrip("\n").split("=", 1) for linha in f if "=" in linha and not linha.startswith("#"))


def gravar_env(novos):
    valores = {**ler_env(), **novos}
    os.makedirs(os.path.dirname(ENV), exist_ok=True)
    tmp = ENV + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.writelines(f"{k}={v}\n" for k, v in valores.items())
    os.chmod(tmp, 0o600)
    try:
        dono = pwd.getpwnam("sisifo")
        os.chown(tmp, dono.pw_uid, dono.pw_gid)
    except (KeyError, PermissionError):
        pass
    os.replace(tmp, ENV)


def chamar(url, dados=None, token=None):
    pedido = urllib.request.Request(url, data=urllib.parse.urlencode(dados).encode() if dados else None)
    if token:
        pedido.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(pedido, timeout=30) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        corpo = json.loads(e.read() or b"{}")
        erro = corpo.get("error_description") or corpo.get("error") or e.reason
        if isinstance(erro, dict):
            erro = erro.get("message", "erro desconhecido")
        falha(f"o Google respondeu {e.code}: {erro}", "rode o script de novo; se repetir, mande esta mensagem (ela não tem segredo).")
    except urllib.error.URLError as e:
        falha(f"sem conexão com o Google ({e.reason})", "confira a internet da VPS e rode de novo.")


def pkce():
    verificador = secrets.token_urlsafe(64)
    desafio = base64.urlsafe_b64encode(hashlib.sha256(verificador.encode()).digest()).rstrip(b"=").decode()
    return verificador, desafio


def ler_volta(endereco, estado):
    q = urllib.parse.parse_qs(urllib.parse.urlparse(endereco.strip()).query)
    if "error" in q:
        falha(f"o Google não autorizou ({q['error'][0]})", "rode de novo e clique em Continuar/Permitir no fim.")
    if q.get("state") != [estado]:
        falha("esse endereço é de outra tentativa", "rode o script de novo e use o endereço novo.")
    if "code" not in q:
        falha("o endereço colado não tem o código", "copie o endereço INTEIRO da barra, depois do Permitir.")
    return q["code"][0]


def principal():
    print("Noema Analytics: autorizar leitura do YouTube\n")
    cid = input("1) Cole o ID do cliente e aperte Enter: ").strip()
    if not cid.endswith(".apps.googleusercontent.com"):
        falha("isso não parece um ID de cliente (termina em .apps.googleusercontent.com)", "copie o ID de novo no Google Cloud.")
    chave = getpass.getpass("2) Cole a chave secreta (não aparece na tela) e aperte Enter: ").strip()
    if not chave:
        falha("chave secreta vazia", "copie a chave secreta de novo e rode outra vez.")
    gravar_env({"YT_CLIENT_ID": cid, "YT_CLIENT_SECRET": chave})

    verificador, desafio = pkce()
    estado = secrets.token_urlsafe(16)
    url = AUTH + "?" + urllib.parse.urlencode({
        "client_id": cid, "redirect_uri": REDIRECT, "response_type": "code", "scope": " ".join(SCOPES),
        "access_type": "offline", "prompt": "consent", "code_challenge": desafio, "code_challenge_method": "S256", "state": estado})
    print("\n3) Abra este endereço numa JANELA ANÔNIMA do Chrome:\n\n" + url + "\n")
    print("   - Entre com a conta DONA do canal @noema_ia (não a arthurhenriquedepaula88).")
    print("   - Se aparecer 'O Google não verificou este app': clique em Avançado e depois em 'Acessar Noema Analytics'.")
    print("   - Marque as caixas de permissão e clique em Continuar.")
    print("   - Vai abrir uma página de erro 'Não é possível acessar esse site'. É normal.")
    print("   - Copie o endereço INTEIRO da barra dessa página de erro.\n")
    volta = getpass.getpass("4) Cole o endereço (não aparece na tela) e aperte Enter: ")
    codigo = ler_volta(volta, estado)

    tok = chamar(TOKEN, {"code": codigo, "client_id": cid, "client_secret": chave, "redirect_uri": REDIRECT,
                         "grant_type": "authorization_code", "code_verifier": verificador})
    if "refresh_token" not in tok:
        falha("o Google não devolveu o token de longo prazo", "remova o acesso em myaccount.google.com/permissions e rode de novo.")
    dados = set(tok.get("scope", "").split())
    faltando = [s.rsplit("/", 1)[1] for s in SCOPES if s not in dados]
    if faltando:
        chamar(REVOGAR, {"token": tok["refresh_token"]})
        falha(f"faltou marcar a permissão {', '.join(faltando)}", "rode de novo e marque todas as caixas.")

    canais = chamar(CANAIS, token=tok["access_token"]).get("items", [])
    if not canais:
        chamar(REVOGAR, {"token": tok["refresh_token"]})
        falha("essa conta não tem canal no YouTube", "rode de novo e entre com a conta do canal @noema_ia.")
    trecho = canais[0]["snippet"]
    apelido = trecho.get("customUrl", "").lstrip("@").lower()
    if apelido != CANAL:
        chamar(REVOGAR, {"token": tok["refresh_token"]})
        falha(f"você autorizou o canal '{trecho.get('title')}' (@{apelido}), não o @noema_ia. Desfiz esse acesso.",
              "rode de novo e, no login, escolha a conta do canal @noema_ia.")

    gravar_env({"YT_REFRESH_TOKEN": tok["refresh_token"], "YT_CHANNEL_ID": canais[0]["id"]})
    print(f"\nPRONTO: canal '{trecho.get('title')}' (@{apelido}) autorizado só para LEITURA.")
    print(f"Chaves guardadas em {ENV} (só o dono lê: chmod 600). Nada foi mostrado na tela.")


if __name__ == "__main__":
    principal()
