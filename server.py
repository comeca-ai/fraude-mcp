from fastmcp import FastMCP
from openai import OpenAI

mcp = FastMCP(
    "Detector de Fraudes",
    instructions="Analisa prints de WhatsApp e mensagens para detectar golpes e fraudes usando IA avançada."
)

# Configuração do workflow
WORKFLOW_ID = "wf_6944dd03e65481908dfd92f9fc2ec522002546ac8361260f"


@mcp.tool()
def analisar_fraude(texto: str) -> dict:
    """Analisa mensagem ou print de WhatsApp para detectar fraudes e golpes.

    Use quando o usuario enviar um PRINT de WhatsApp, SMS ou email suspeito.
    Extraia o texto completo da imagem e passe para esta ferramenta.

    O agente de IA vai:
    1. Extrair dados estruturados (remetente, mensagens, dados bancarios)
    2. Identificar padroes de comportamento suspeito
    3. Calcular probabilidade de fraude
    4. Identificar o tipo de golpe
    5. Dar recomendacoes de seguranca

    Args:
        texto: Texto extraido da mensagem/print do WhatsApp

    Returns:
        Analise completa com probabilidade de fraude, tipo de golpe e acoes recomendadas
    """
    try:
        client = OpenAI()

        # Criar sessão com o workflow
        session = client.beta.chatkit.sessions.create(
            user="mcp-user",
            workflow={
                "id": WORKFLOW_ID
            }
        )

        # Enviar mensagem para o workflow
        response = client.beta.chatkit.sessions.messages.create(
            session_id=session.id,
            role="user",
            content=texto
        )

        return {
            "status": "sucesso",
            "session_id": session.id,
            "analise": response
        }
    except Exception as e:
        return {
            "status": "erro",
            "mensagem": str(e),
            "dica": "Verifique se a OPENAI_API_KEY esta configurada"
        }


@mcp.tool()
def dicas_antifraude() -> dict:
    """Retorna dicas para se proteger de golpes e fraudes.

    Use quando o usuario pedir orientacoes gerais sobre seguranca."""

    return {
        "golpes_mais_comuns": [
            {
                "nome": "Golpe do Falso Parente",
                "como_funciona": "Golpista usa numero novo fingindo ser familiar pedindo dinheiro urgente",
                "como_evitar": "SEMPRE ligue para o numero antigo do familiar para confirmar"
            },
            {
                "nome": "Golpe do Falso Funcionario",
                "como_funciona": "Ligam dizendo ser do banco pedindo dados ou transferencia",
                "como_evitar": "Bancos NUNCA ligam pedindo senha ou dados. Desligue e ligue para o numero oficial."
            },
            {
                "nome": "Golpe do PIX",
                "como_funciona": "Pedem PIX urgente para 'corrigir erro' ou conta de terceiro",
                "como_evitar": "Desconfie de contas com titulares diferentes do esperado"
            },
            {
                "nome": "Phishing",
                "como_funciona": "Emails/SMS falsos com links para roubar dados",
                "como_evitar": "Nunca clique em links. Acesse o site digitando o endereco oficial."
            }
        ],
        "red_flags": [
            "Numero desconhecido pedindo transferencia",
            "Conta bancaria com nome de terceiro",
            "Urgencia excessiva ('preciso agora', 'so ate hoje')",
            "Ligacao perdida seguida de dados bancarios",
            "Pedido de senha, CVV, token ou codigo SMS"
        ],
        "regras_de_ouro": [
            "Bancos NUNCA pedem senha por telefone/mensagem",
            "Desconfie de URGENCIA - golpistas criam pressao",
            "Na duvida, DESLIGUE e ligue para o numero oficial",
            "NUNCA clique em links de mensagens",
            "Confirme por LIGACAO (numero antigo) antes de transferir"
        ],
        "se_cair_em_golpe": [
            "Ligue IMEDIATAMENTE para o banco e peca bloqueio",
            "Solicite estorno via MED (Mecanismo Especial de Devolucao)",
            "Faca Boletim de Ocorrencia",
            "Guarde todos os prints e evidencias"
        ]
    }
