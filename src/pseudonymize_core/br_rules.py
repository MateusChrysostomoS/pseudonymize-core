"""Regras de detecção de PII específicas do Brasil.

Separado do motor (`engine.py`) de propósito: o mecanismo de tokenização/
re-hidratação é genérico, mas TUDO neste arquivo é ajuste fino de conformidade
brasileira — o formato do CPF, o nono dígito do celular, as partículas de nome
em português, as classes de acento. É a parte que muda se a biblioteca for
usada fora do Brasil, e a que NÃO deveria sair junto se um dia só o motor for
publicado.

Nada aqui faz I/O. São tabelas e regexes.
"""

from __future__ import annotations

import re

# Partículas de nome que nunca viram termo de busca sozinhas (curtas e comuns
# demais — "da", "dos" apareceriam no meio de qualquer texto clínico).
NAME_STOPWORDS = frozenset(
    {"de", "da", "do", "das", "dos", "e", "di", "du", "del", "la", "van", "von"}
)

# Comprimento mínimo de um termo para virar regra de substituição. Abaixo disso o
# risco de destruir texto clínico supera o ganho (ver também o \b obrigatório).
MIN_TERM_LEN = 3

# Classes que tornam a busca insensível a acento sem mexer no comprimento da
# string (NFKD mudaria o tamanho e quebraria as posições do re.sub).
ACCENT_CLASSES = {
    "a": "aáàâãä",
    "e": "eéèêë",
    "i": "iíìîï",
    "o": "oóòôõö",
    "u": "uúùûü",
    "c": "cç",
    "n": "nñ",
}

CPF_RE = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
# Telefone BR com DDD (10 ou 11 dígitos), com ou sem máscara/+55. Exige o DDD
# entre parênteses ou um separador depois dele para não capturar qualquer
# sequência longa de dígitos (número de exame, código de convênio).
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?55[\s.-]?)?(?:\(\d{2}\)|\d{2})[\s.-]?9?\d{4}[\s.-]?\d{4}(?!\d)"
)

# A ORDEM É INVARIANTE, não estilo. E-mail primeiro: se o nome ou o telefone
# rodasse antes, "joao@teste.com" viraria "[PACIENTE_x]@teste.com" e o domínio
# vazaria. Telefone antes de CPF: um celular de 11 dígitos sem máscara casa com
# a regex de CPF, e o rótulo do token ficaria errado.
PATTERN_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (EMAIL_RE, "EMAIL"),
    (PHONE_RE, "TELEFONE"),
    (CPF_RE, "CPF"),
)


def redact_patterns(text: str) -> str:
    """Mascaramento IRREVERSÍVEL de e-mail/telefone/CPF, para chamadas de IA cujo
    resultado nunca volta a ser texto persistido — hoje o `ai_classifier`, que
    devolve só um rótulo. Não usar onde o texto precisa ser re-hidratado
    (aí é o `Pseudonymizer`). Nome do paciente fica de fora: o classificador
    não sabe quem é o paciente, só vê a mensagem atual."""
    if not text:
        return text
    text = EMAIL_RE.sub("[e-mail omitido]", text)
    text = PHONE_RE.sub("[telefone omitido]", text)
    return CPF_RE.sub("[CPF omitido]", text)
