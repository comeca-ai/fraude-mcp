from fastmcp import FastMCP
from agents import Agent, Runner

mcp = FastMCP(
    "Detector de Fraudes",
    instructions="Analisa prints de WhatsApp para detectar golpes. Use APENAS a ferramenta analisar_fraude."
)

# Agente 1: Triagem - extrai dados
agente_triagem = Agent(
    name="Agente triagem",
    instructions="""# AGENTE DE TRIAGEM

Extraia dados de conversas suspeitas em JSON. Anonimize dados sensíveis.

## Anonimização
- Telefones → [TELEFONE_REMETENTE]
- Nomes → [NOME_TITULAR]
- CPF → [CPF_OCULTADO]
- Conta → formato XXXXX-X
- Agência → formato XXXX

## Extrair
1. Metadados: horário, bateria, operadora, conexão
2. Remetente: tipo (salvo/desconhecido), DDD, região
3. Interações: ligações perdidas, horários
4. Mensagens: autor, texto, horário, sequência
5. Dados financeiros: banco, titular, agência, conta, PIX, valor
6. Links: domínios, encurtadores, suspeitos
7. Padrões: insistência, urgência, mudança de assunto
8. Contexto: app, tema, tom emocional

Retorne APENAS JSON estruturado.""",
    model="gpt-4o",
    tools=[]  # Sem ferramentas extras
)

# Agente 2: Detector - analisa fraude
agente_fraude = Agent(
    name="Agente de fraude",
    instructions="""# AGENTE DETECTOR DE FRAUDE

Analise dados anonimizados e determine probabilidade de golpe.

## Critérios e Pesos
- Ligação perdida → dados bancários: 35%
- Conta de terceiro: 30%
- Número desconhecido + pagamento: 30%
- Insistência/mensagens seguidas: 25%
- Mudança abrupta para dinheiro: 20%
- PIX/transferência solicitada: 35%
- Domínio falso: 35%
- Ameaça de bloqueio: 25%
- Finge ser banco/parente: 25%

## Tipos de Golpe
1. Falso parente ("mudei de número")
2. Falso banco ("compra suspeita")
3. Falso Correios ("taxa de liberação")
4. Clonagem WhatsApp (pede código)
5. PIX errado ("devolve")
6. Falso sequestro

## Níveis
- 0-20%: 🟢 BAIXO
- 21-50%: 🟡 MÉDIO
- 51-100%: 🔴 ALTO

Retorne APENAS JSON com: probabilidade, nivel_risco, criterios_detectados, tipo_golpe_identificado, red_flags, recomendacao_principal, acoes_imediatas, se_ja_transferiu""",
    model="gpt-4o",
    tools=[]  # Sem ferramentas extras
)


@mcp.tool()
async def analisar_fraude(texto: str) -> dict:
    """Analisa print de WhatsApp para detectar fraudes.

    Extraia o texto da imagem e passe para esta ferramenta.
    Executa 2 agentes: Triagem → Detector.

    Args:
        texto: Texto extraido do print

    Returns:
        JSON com triagem e analise de fraude
    """
    runner = Runner()

    # Agente 1: Triagem
    triagem = await runner.run(
        agente_triagem,
        input=texto
    )

    # Agente 2: Fraude
    fraude = await runner.run(
        agente_fraude,
        input=triagem.final_output
    )

    return {
        "triagem": triagem.final_output,
        "analise": fraude.final_output
    }
