from fastmcp import FastMCP
import re
import hashlib
import random
from datetime import datetime

mcp = FastMCP("detector-fraude")

# Base de dados simulada de fraudes conhecidas
FRAUDES_CONHECIDAS = {
    "emails": [
        "suporte@banco-falso.com",
        "atendimento@bb-seguro.net",
        "contato@nubank-promo.com",
        "sac@itau-ofertas.xyz"
    ],
    "telefones": [
        "11999999999",
        "21988888888"
    ],
    "dominios_suspeitos": [
        "banco-falso.com",
        "bb-seguro.net",
        "nubank-promo.com",
        "itau-ofertas.xyz",
        "caixa-gov.net",
        "bradesco-app.com"
    ],
    "palavras_golpe": [
        "urgente", "bloqueado", "suspensa", "cancelado",
        "clique aqui", "atualize agora", "confirme seus dados",
        "premio", "sorteado", "ganhou", "gratis",
        "deposito", "pix", "transferencia"
    ]
}


def calcular_score_risco(indicadores: list) -> dict:
    """Calcula score de risco baseado nos indicadores encontrados."""
    score = len(indicadores) * 20
    score = min(score, 100)

    if score < 30:
        nivel = "BAIXO"
        cor = "verde"
    elif score < 60:
        nivel = "MEDIO"
        cor = "amarelo"
    elif score < 80:
        nivel = "ALTO"
        cor = "laranja"
    else:
        nivel = "CRITICO"
        cor = "vermelho"

    return {
        "score": score,
        "nivel": nivel,
        "cor": cor
    }


@mcp.tool()
def analisar_mensagem(texto: str) -> dict:
    """Analisa uma mensagem (SMS, WhatsApp, email) para detectar sinais de golpe.

    Use this when user receives a suspicious message and wants to know if it's a scam.

    Args:
        texto: Conteudo da mensagem recebida
    """

    texto_lower = texto.lower()
    indicadores = []
    detalhes = []

    # Verificar palavras de golpe
    for palavra in FRAUDES_CONHECIDAS["palavras_golpe"]:
        if palavra in texto_lower:
            indicadores.append(f"palavra_suspeita:{palavra}")
            detalhes.append(f"Contem palavra suspeita: '{palavra}'")

    # Verificar URLs suspeitas
    urls = re.findall(r'https?://[^\s]+', texto)
    for url in urls:
        # Verificar encurtadores
        if any(enc in url for enc in ["bit.ly", "tinyurl", "goo.gl", "t.co"]):
            indicadores.append("url_encurtada")
            detalhes.append(f"URL encurtada (pode esconder destino malicioso): {url}")

        # Verificar dominios suspeitos
        for dominio in FRAUDES_CONHECIDAS["dominios_suspeitos"]:
            if dominio in url:
                indicadores.append(f"dominio_fraudulento:{dominio}")
                detalhes.append(f"Dominio conhecido por fraudes: {dominio}")

    # Verificar pedido de dados pessoais
    dados_sensiveis = ["cpf", "senha", "cartao", "cvv", "codigo", "token", "agencia", "conta"]
    for dado in dados_sensiveis:
        if dado in texto_lower:
            indicadores.append(f"pede_dado_sensivel:{dado}")
            detalhes.append(f"Solicita dado sensivel: {dado}")

    # Verificar urgencia artificial
    urgencia = ["imediato", "urgente", "agora", "ultima chance", "expira hoje", "24 horas", "bloqueio"]
    for u in urgencia:
        if u in texto_lower:
            indicadores.append("urgencia_artificial")
            detalhes.append(f"Cria senso de urgencia: '{u}'")
            break

    # Verificar erros de portugues (indicador de golpe)
    erros_comuns = ["voce foi", "seu conta", "click", "atualizacao"]
    for erro in erros_comuns:
        if erro in texto_lower:
            indicadores.append("erro_portugues")
            detalhes.append("Possivel erro de portugues (comum em golpes)")
            break

    risco = calcular_score_risco(indicadores)

    # Recomendacao
    if risco["nivel"] == "CRITICO":
        recomendacao = "NAO CLIQUE EM NADA! Esta mensagem tem todas as caracteristicas de um golpe. Delete imediatamente."
    elif risco["nivel"] == "ALTO":
        recomendacao = "Muito provavelmente e um golpe. Nao clique em links e nao forneca dados. Verifique diretamente com a empresa pelo site/app oficial."
    elif risco["nivel"] == "MEDIO":
        recomendacao = "Mensagem suspeita. Nao clique em links. Entre em contato com a empresa por canais oficiais para confirmar."
    else:
        recomendacao = "Risco baixo, mas sempre verifique links antes de clicar e nunca forneca senhas por mensagem."

    return {
        "risco": risco,
        "indicadores_encontrados": len(indicadores),
        "detalhes": detalhes,
        "recomendacao": recomendacao,
        "dica": "Bancos NUNCA pedem senha, CVV ou token por mensagem/ligacao."
    }


@mcp.tool()
def verificar_link(url: str) -> dict:
    """Verifica se um link e seguro ou suspeito.

    Use this when user wants to check if a URL is safe before clicking.

    Args:
        url: URL completa para verificar
    """

    indicadores = []
    alertas = []

    url_lower = url.lower()

    # Verificar protocolo
    if not url_lower.startswith("https://"):
        indicadores.append("sem_https")
        alertas.append("Site nao usa HTTPS (conexao nao segura)")

    # Verificar encurtadores
    encurtadores = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd"]
    for enc in encurtadores:
        if enc in url_lower:
            indicadores.append("url_encurtada")
            alertas.append(f"URL encurtada ({enc}) - destino real oculto")

    # Verificar dominios suspeitos
    for dominio in FRAUDES_CONHECIDAS["dominios_suspeitos"]:
        if dominio in url_lower:
            indicadores.append("dominio_fraudulento")
            alertas.append(f"Dominio conhecido por fraudes: {dominio}")

    # Verificar typosquatting (dominios parecidos com legitimos)
    typos = {
        "amaz0n": "amazon",
        "g00gle": "google",
        "facebok": "facebook",
        "mercadoliivre": "mercadolivre",
        "nuubank": "nubank",
        "bradesc0": "bradesco",
        "ltau": "itau"
    }
    for typo, correto in typos.items():
        if typo in url_lower:
            indicadores.append("typosquatting")
            alertas.append(f"Dominio similar a '{correto}' (possivel typosquatting)")

    # Verificar excesso de subdomínios
    partes = url_lower.replace("https://", "").replace("http://", "").split("/")[0].split(".")
    if len(partes) > 4:
        indicadores.append("muitos_subdominios")
        alertas.append("Excesso de subdominios (tecnica comum de phishing)")

    # Verificar IP no lugar de dominio
    if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url_lower):
        indicadores.append("ip_direto")
        alertas.append("URL usa IP em vez de dominio (muito suspeito)")

    risco = calcular_score_risco(indicadores)

    # Recomendacao
    if risco["nivel"] in ["CRITICO", "ALTO"]:
        recomendacao = "NAO ACESSE este link! Alta probabilidade de ser phishing ou malware."
    elif risco["nivel"] == "MEDIO":
        recomendacao = "Link suspeito. Se precisar acessar, digite o endereco oficial manualmente no navegador."
    else:
        recomendacao = "Link parece seguro, mas sempre verifique o cadeado de seguranca no navegador."

    return {
        "url_analisada": url,
        "risco": risco,
        "alertas": alertas,
        "recomendacao": recomendacao,
        "dica": "Na duvida, acesse o site digitando o endereco oficial diretamente no navegador."
    }


@mcp.tool()
def verificar_email_remetente(email: str) -> dict:
    """Verifica se um email de remetente e legitimo ou suspeito.

    Use this when user wants to verify if an email sender is legitimate.

    Args:
        email: Endereco de email do remetente
    """

    indicadores = []
    alertas = []

    email_lower = email.lower()

    # Verificar se esta na lista de fraudes conhecidas
    if email_lower in FRAUDES_CONHECIDAS["emails"]:
        indicadores.append("email_fraudulento_conhecido")
        alertas.append("Email cadastrado em nossa base de fraudes!")

    # Extrair dominio
    if "@" in email_lower:
        dominio = email_lower.split("@")[1]

        # Verificar dominios suspeitos
        for dom_sus in FRAUDES_CONHECIDAS["dominios_suspeitos"]:
            if dom_sus in dominio:
                indicadores.append("dominio_suspeito")
                alertas.append(f"Dominio suspeito: {dominio}")

        # Verificar dominios genericos para emails "oficiais"
        genericos = ["gmail.com", "hotmail.com", "yahoo.com", "outlook.com"]
        palavras_oficiais = ["banco", "suporte", "atendimento", "sac", "contato"]

        nome_email = email_lower.split("@")[0]
        if dominio in genericos and any(p in nome_email for p in palavras_oficiais):
            indicadores.append("email_generico_fingindo_oficial")
            alertas.append("Email generico se passando por oficial (bancos usam dominio proprio)")

        # Verificar dominios parecidos com legitimos
        dominios_legitimos = {
            "nubank.com.br": ["nubank", "nu-bank", "nuubank"],
            "itau.com.br": ["itau", "ltau", "1tau"],
            "bradesco.com.br": ["bradesco", "bradesc0"],
            "bb.com.br": ["bb", "bancodobrasil"],
            "caixa.gov.br": ["caixa", "cef"]
        }

        for legit, similares in dominios_legitimos.items():
            for similar in similares:
                if similar in dominio and dominio != legit:
                    indicadores.append("dominio_similar_fraude")
                    alertas.append(f"Dominio '{dominio}' similar ao legitimo '{legit}'")

    risco = calcular_score_risco(indicadores)

    # Informacoes sobre dominios legitimos de bancos
    dominios_oficiais = {
        "Nubank": "nubank.com.br",
        "Itau": "itau.com.br",
        "Bradesco": "bradesco.com.br",
        "Banco do Brasil": "bb.com.br",
        "Caixa": "caixa.gov.br",
        "Santander": "santander.com.br"
    }

    return {
        "email_analisado": email,
        "risco": risco,
        "alertas": alertas,
        "dominios_oficiais_bancos": dominios_oficiais,
        "dica": "Bancos sempre usam seu dominio oficial. Desconfie de @gmail, @hotmail, etc."
    }


@mcp.tool()
def verificar_telefone(telefone: str) -> dict:
    """Verifica se um numero de telefone e suspeito.

    Use this when user receives a call or message from an unknown number.

    Args:
        telefone: Numero de telefone (com ou sem DDD)
    """

    # Limpar telefone (remover caracteres especiais)
    telefone_limpo = re.sub(r'[^\d]', '', telefone)

    indicadores = []
    alertas = []
    info = {}

    # Verificar se esta na lista de fraudes
    if telefone_limpo in FRAUDES_CONHECIDAS["telefones"]:
        indicadores.append("telefone_fraudulento_conhecido")
        alertas.append("Telefone cadastrado em nossa base de fraudes!")

    # Analisar DDD
    if len(telefone_limpo) >= 10:
        ddd = telefone_limpo[:2] if len(telefone_limpo) == 10 else telefone_limpo[:2]
        info["ddd"] = ddd

        # DDDs validos do Brasil
        ddds_validos = list(range(11, 100))
        if int(ddd) not in ddds_validos:
            indicadores.append("ddd_invalido")
            alertas.append(f"DDD {ddd} nao e valido no Brasil")

    # Verificar se e celular ou fixo
    if len(telefone_limpo) >= 9:
        primeiro_digito = telefone_limpo[-9] if len(telefone_limpo) >= 11 else telefone_limpo[-8]
        if primeiro_digito == "9":
            info["tipo"] = "celular"
        else:
            info["tipo"] = "fixo"

    # Verificar numeros curtos (SAC, etc)
    if len(telefone_limpo) <= 5:
        info["tipo"] = "numero_curto_sac"
        alertas.append("Numero curto - pode ser SAC legitimo, mas golpistas tambem usam")

    risco = calcular_score_risco(indicadores)

    return {
        "telefone_analisado": telefone,
        "telefone_formatado": telefone_limpo,
        "info": info,
        "risco": risco,
        "alertas": alertas,
        "recomendacao": "Bancos raramente ligam pedindo dados. Na duvida, desligue e ligue voce para o numero oficial.",
        "numeros_oficiais": {
            "Nubank": "4020-0185",
            "Itau": "4004-4828",
            "Bradesco": "4002-0022",
            "BB": "4004-0001",
            "Caixa": "4004-0104"
        }
    }


@mcp.tool()
def dicas_antifraude() -> dict:
    """Retorna dicas para se proteger de golpes e fraudes.

    Use this when user asks for tips on avoiding scams."""

    return {
        "golpes_mais_comuns": [
            {
                "nome": "Golpe do Falso Funcionario",
                "como_funciona": "Ligam dizendo ser do banco pedindo dados ou que faca transferencia",
                "como_evitar": "Bancos NUNCA ligam pedindo senha ou dados. Desligue e ligue para o numero oficial."
            },
            {
                "nome": "Golpe do PIX",
                "como_funciona": "Pedem PIX urgente se passando por familiar ou para 'corrigir erro'",
                "como_evitar": "Sempre confirme por ligacao (nao WhatsApp) antes de fazer PIX"
            },
            {
                "nome": "Phishing",
                "como_funciona": "Emails/SMS falsos com links para roubar dados",
                "como_evitar": "Nunca clique em links. Acesse o site digitando o endereco oficial."
            },
            {
                "nome": "Golpe do WhatsApp Clonado",
                "como_funciona": "Usam foto de conhecido pedindo dinheiro",
                "como_evitar": "Ligue para confirmar. Nunca envie dinheiro sem falar por voz."
            },
            {
                "nome": "Falso Boleto",
                "como_funciona": "Boleto adulterado que envia dinheiro para golpista",
                "como_evitar": "Confira os dados do beneficiario antes de pagar. Use DDA quando possivel."
            }
        ],
        "regras_de_ouro": [
            "Bancos NUNCA pedem senha, CVV ou token por telefone/mensagem",
            "Desconfie de URGENCIA - golpistas criam pressao para voce nao pensar",
            "Na duvida, DESLIGUE e ligue voce para o numero oficial",
            "NUNCA clique em links de mensagens - digite o site manualmente",
            "Ative autenticacao em duas etapas em tudo"
        ],
        "o_que_fazer_se_cair_em_golpe": [
            "Ligue imediatamente para o banco e bloqueie cartoes/contas",
            "Faca boletim de ocorrencia online ou presencial",
            "Registre reclamacao no Banco Central (se envolver banco)",
            "Guarde todas as evidencias (prints, numeros, emails)"
        ],
        "contatos_uteis": {
            "Banco Central (denuncias)": "145",
            "PROCON": "151",
            "Policia Civil (BO online)": "Acesse o site da PC do seu estado",
            "SaferNet (crimes digitais)": "www.safernet.org.br"
        }
    }


@mcp.tool()
def reportar_fraude(
    tipo: str,
    descricao: str,
    contato_fraudador: str = None
) -> dict:
    """Registra uma denuncia de fraude para ajudar outros usuarios.

    Use this when user wants to report a scam they encountered.

    Args:
        tipo: Tipo de fraude (phishing, ligacao, whatsapp, boleto, outro)
        descricao: Descricao do golpe
        contato_fraudador: Email, telefone ou link usado pelo golpista (opcional)
    """

    # Gerar ID do report
    report_id = f"FRD-{random.randint(100000, 999999)}"
    data_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return {
        "report_id": report_id,
        "status": "REGISTRADO",
        "data_hora": data_hora,
        "tipo": tipo,
        "descricao": descricao,
        "contato_fraudador": contato_fraudador,
        "mensagem": "Denuncia registrada com sucesso! Obrigado por ajudar a proteger outros usuarios.",
        "proximos_passos": [
            "Faca um boletim de ocorrencia na Policia Civil",
            "Se envolver banco, registre reclamacao no Banco Central (145)",
            "Bloqueie o numero/email do golpista"
        ]
    }
