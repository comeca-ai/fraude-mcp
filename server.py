from fastmcp import FastMCP
from agents import Agent, Runner

mcp = FastMCP(
    "Detector de Fraudes",
    instructions="Analisa prints de WhatsApp e mensagens para detectar golpes e fraudes."
)

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

1. **Metadados**: horário, bateria, operadora, conexão
2. **Remetente**: tipo (salvo/desconhecido), DDD, região
3. **Interações**: ligações perdidas, horários
4. **Mensagens**: autor, texto, horário, sequência
5. **Dados financeiros**: banco, titular, agência, conta, PIX, valor
6. **Links**: domínios, encurtadores, suspeitos
7. **Padrões**: insistência, urgência, mudança de assunto
8. **Contexto**: app, tema, tom emocional

## Saída JSON
```json
{
  "metadados_dispositivo": {},
  "remetente": {},
  "historico_interacoes": {},
  "mensagens": [],
  "dados_financeiros": {},
  "links": {},
  "padroes_comportamento": {},
  "contexto": {}
}
```

## Regras
- Dados reais → tokens anonimizados
- Extraia só o visível
- Capture padrões suspeitos""",
    model="gpt-4.1"
)

agente_fraude = Agent(
    name="Agente de fraude",
    instructions="""# AGENTE DETECTOR DE FRAUDE

Analise dados anonimizados e determine probabilidade de golpe.

## Critérios e Pesos

### Comportamento (alto impacto)
- Ligação perdida → dados bancários: 35%
- Conta de terceiro: 30%
- Número desconhecido + pagamento: 30%
- Insistência/mensagens seguidas: 25%
- Mudança abrupta para dinheiro: 20%

### Dados Financeiros
- PIX/transferência solicitada: 35%
- Titular ≠ contexto: 30%
- Valor + urgência: 25%

### Links
- Domínio falso (.click, .tk): 35%
- Encurtador sem contexto: 25%

### Comunicação
- Ameaça de bloqueio: 25%
- Urgência explícita: 20%
- Finge ser banco/parente: 25%

## Tipos de Golpe
1. Falso parente ("mudei de número")
2. Falso banco ("compra suspeita")
3. Falso Correios ("taxa de liberação")
4. Clonagem WhatsApp (pede código)
5. PIX errado ("devolve")
6. Falso sequestro

## Níveis
| Prob | Nível | Ação |
|------|-------|------|
| 0-20% | 🟢 BAIXO | Confirme por outro canal |
| 21-50% | 🟡 MÉDIO | NÃO clique, verifique |
| 51-100% | 🔴 ALTO | GOLPE - Bloqueie |

## Saída JSON
```json
{
  "probabilidade": 90,
  "nivel_risco": "ALTO",
  "criterios_detectados": [
    {"criterio": "...", "peso": 35, "evidencia": "..."}
  ],
  "tipo_golpe_identificado": "Falso parente",
  "red_flags": ["..."],
  "recomendacao_principal": "NÃO TRANSFIRA",
  "acoes_imediatas": ["Bloqueie", "Denuncie"],
  "se_ja_transferiu": ["Ligue pro banco", "Faça B.O."]
}
```

## Regras
- Na dúvida, aumente a probabilidade
- Explique cada critério com evidência
- Ações práticas e específicas
- Orientações para quem já caiu""",
    model="gpt-4.1"
)


@mcp.tool()
async def analisar_fraude(texto: str) -> dict:
    """Analisa mensagem ou print de WhatsApp para detectar fraudes.

    Use quando o usuario enviar um PRINT de WhatsApp, SMS ou email suspeito.
    Extraia o texto completo da imagem e passe para esta ferramenta.

    Executa 2 agentes em sequência:
    1. Triagem: extrai e anonimiza dados
    2. Detector: analisa e calcula probabilidade de fraude

    Args:
        texto: Texto extraido da mensagem/print do WhatsApp

    Returns:
        Analise completa com probabilidade, tipo de golpe e acoes recomendadas
    """
    try:
        runner = Runner()

        # Agente 1: Triagem
        resultado_triagem = await runner.run(
            agente_triagem,
            [{"role": "user", "content": texto}]
        )

        # Agente 2: Fraude (recebe histórico com resultado da triagem)
        historico = [
            {"role": "user", "content": texto},
            {"role": "assistant", "content": resultado_triagem.final_output}
        ]

        resultado_fraude = await runner.run(
            agente_fraude,
            historico
        )

        return {
            "status": "sucesso",
            "triagem": resultado_triagem.final_output,
            "analise": resultado_fraude.final_output
        }
    except Exception as e:
        return {
            "status": "erro",
            "mensagem": str(e),
            "dica": "Verifique se a OPENAI_API_KEY esta configurada"
        }


@mcp.tool()
def dicas_antifraude() -> dict:
    """Retorna dicas para se proteger de golpes e fraudes."""

    return {
        "tipos_de_golpe": [
            {"nome": "Falso parente", "sinal": "Oi, mudei de número"},
            {"nome": "Falso banco", "sinal": "Detectamos compra suspeita"},
            {"nome": "Falso Correios", "sinal": "Taxa de liberação"},
            {"nome": "Clonagem WhatsApp", "sinal": "Pede código SMS"},
            {"nome": "PIX errado", "sinal": "Mandei errado, devolve"},
            {"nome": "Falso sequestro", "sinal": "Pressão extrema, choro"}
        ],
        "red_flags": [
            "Número desconhecido pedindo dinheiro",
            "Conta bancária com nome de terceiro",
            "Urgência excessiva",
            "Pedido de senha, CVV ou código"
        ],
        "regras_de_ouro": [
            "Bancos NUNCA pedem senha por telefone",
            "Desconfie de URGÊNCIA",
            "Confirme por LIGAÇÃO no número antigo",
            "NUNCA clique em links de mensagens"
        ],
        "se_cair_em_golpe": [
            "Ligue pro banco IMEDIATAMENTE",
            "Peça bloqueio via MED",
            "Faça B.O. online",
            "Guarde prints"
        ]
    }
