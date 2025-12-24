from fastmcp import FastMCP
from openai import OpenAI
import time

mcp = FastMCP(
    "Detector de Fraudes",
    instructions="Analisa prints de WhatsApp para detectar golpes. Use APENAS a ferramenta analisar_fraude."
)

ASSISTANT_ID = "asst_JIzzruVEiqDG2U2edak3d2vE"


@mcp.tool()
def analisar_fraude(texto: str) -> dict:
    """Analisa print de WhatsApp para detectar fraudes.

    Extraia o texto da imagem e passe para esta ferramenta.
    Chama o Agente de Fraude da OpenAI.

    Args:
        texto: Texto extraido do print

    Returns:
        Analise de fraude do agente
    """
    client = OpenAI()

    # Criar thread
    thread = client.beta.threads.create()

    # Adicionar mensagem
    client.beta.threads.messages.create(
        thread_id=thread.id,
        role="user",
        content=texto
    )

    # Executar assistant
    run = client.beta.threads.runs.create(
        thread_id=thread.id,
        assistant_id=ASSISTANT_ID
    )

    # Aguardar conclusão
    while run.status in ["queued", "in_progress"]:
        time.sleep(1)
        run = client.beta.threads.runs.retrieve(
            thread_id=thread.id,
            run_id=run.id
        )

    # Pegar resposta
    messages = client.beta.threads.messages.list(thread_id=thread.id)

    # Extrair última resposta do assistant
    for msg in messages.data:
        if msg.role == "assistant":
            content = msg.content[0].text.value if msg.content else ""
            return {
                "status": "sucesso",
                "thread_id": thread.id,
                "analise": content
            }

    return {
        "status": "erro",
        "mensagem": "Sem resposta do assistant"
    }
