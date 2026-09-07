"""pseudonymize-core: pseudonimização reversível de PII, stateless.

Compartilhada pelos serviços da Brain Co. Substitui identificadores diretos
(nome, telefone, CPF, e-mail) por tokens reversíveis ANTES de o material sair
para uma API de IA no exterior, e re-hidrata os tokens com os valores reais na
volta, dentro da nossa infra.

    payload de saída  ──► scrub      ──► [PACIENTE_a7f3] vai pro prompt
    resposta da IA    ──► rehydrate  ──► "João da Silva" volta antes de persistir

Restrições de design — a biblioteca NÃO acessa banco, NÃO faz I/O, NÃO lê
variável de ambiente, NÃO chama rede e NÃO loga. Ela só transforma texto. O mapa
de tokens vive em memória num `Pseudonymizer`; persistir esse mapa (e apagá-lo
depois) é responsabilidade de quem chama. Dependências de runtime: nenhuma
(stdlib pura — `re`, `secrets`, `unicodedata`).

⚠️ Isto é PSEUDONIMIZAÇÃO, não anonimização. Dado pseudonimizado continua sendo
dado pessoal (LGPD art. 13, §4º) — o chamador guarda a chave. A biblioteca é
medida de segurança/minimização (art. 46); NÃO dispensa o mecanismo de
transferência internacional (art. 33) nem o consentimento específico do termo.

As regras de detecção são específicas do Brasil e vivem em `br_rules.py`; o
mecanismo genérico de tokenização vive em `engine.py`.
"""

from .br_rules import redact_patterns
from .engine import Pseudonymizer, has_unresolved_tokens

__version__ = "0.1.0"

__all__ = [
    "Pseudonymizer",
    "redact_patterns",
    "has_unresolved_tokens",
    "__version__",
]
