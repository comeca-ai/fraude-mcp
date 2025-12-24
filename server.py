from fastmcp import FastMCP
from openai import OpenAI

mcp = FastMCP(
    "Detector de Fraudes",
    instructions="Analisa prints de WhatsApp para detectar golpes. Use APENAS a ferramenta analisar_fraude."
)

WORKFLOW_ID = "wf_6944dd03e65481908dfd92f9fc2ec522002546ac8361260f"


@mcp.tool()
def analisar_fraude(texto: str) -> dict:
    """Analisa print de WhatsApp para detectar fraudes.

    Extraia o texto da imagem e passe para esta ferramenta.
    Chama o workflow com 2 agentes: Triagem → Detector.

    Args:
        texto: Texto extraido do print

    Returns:
        JSON com triagem e analise de fraude
    """
    client = OpenAI()

    # Criar sessão com o workflow
    session = client.beta.chatkit.sessions.create(
        user="mcp-user",
        workflow={"id": WORKFLOW_ID}
    )

    # Enviar mensagem e aguardar resposta
    response = client.beta.chatkit.sessions.turns.create(
        session_id=session.id,
        messages=[{"role": "user", "content": texto}]
    )

    # Extrair output
    output = ""
    for item in response.items:
        if hasattr(item, 'content'):
            output = item.content

    return {
        "session_id": session.id,
        "resultado": output
    }
