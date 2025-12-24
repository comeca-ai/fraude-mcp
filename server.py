from fastmcp import FastMCP
from openai import OpenAI

mcp = FastMCP(
    "Detector de Fraudes",
    instructions="Analisa prints de WhatsApp para detectar golpes. Use APENAS a ferramenta analisar_fraude."
)

PROMPT_ID = "pmpt_694b72e4e4fc8195891e934667428c4f0294d76a7fdb90cd"
PROMPT_VERSION = "1"


@mcp.tool()
def analisar_fraude(texto: str) -> dict:
    """Analisa print de WhatsApp para detectar fraudes.

    Extraia o texto da imagem e passe para esta ferramenta.
    Chama o prompt de fraude da OpenAI.

    Args:
        texto: Texto extraido do print

    Returns:
        Analise de fraude
    """
    client = OpenAI()

    response = client.responses.create(
        prompt={
            "id": PROMPT_ID,
            "version": PROMPT_VERSION
        },
        input=texto
    )

    return {
        "status": "sucesso",
        "analise": response.output
    }
