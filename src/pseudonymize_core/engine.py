"""Mecanismo genérico de pseudonimização reversível.

Este módulo não sabe o que é um CPF nem o que é um nome brasileiro — ele recebe
as regras de detecção de `br_rules.py` e cuida só do mecanismo: emitir tokens,
guardar o mapa token↔valor, aplicar as substituições na ordem certa e desfazê-las
na volta.

Duas invariantes que sustentam o resto do sistema:

1. **Toda substituição é reversível.** O texto mascarado é lido por HUMANOS depois
   de re-hidratado, não só pela IA — mascarar de forma irreversível (ex.: trocar
   telefone por "[TELEFONE]" fixo) destruiria dado legítimo. Por isso cada valor
   descoberto ganha um token próprio guardado no mapa. (Para o caso em que o
   resultado nunca volta a ser texto persistido, use `redact_patterns`.)
2. **Token nunca é hash do valor.** Hash de nome próprio se quebra por dicionário
   em minutos; o sufixo é aleatório (`secrets`), sem relação com o conteúdo.
"""

from __future__ import annotations

import re
import secrets
import unicodedata
from typing import Any

from .br_rules import ACCENT_CLASSES, MIN_TERM_LEN, NAME_STOPWORDS, PATTERN_RULES

_TOKEN_RE = re.compile(r"\[(?:PACIENTE|CLINICA|TELEFONE|CPF|EMAIL)_[0-9a-f]{4}\]")


def _strip_accents(value: str) -> str:
    return "".join(
        ch for ch in unicodedata.normalize("NFKD", value) if not unicodedata.combining(ch)
    )


def _accent_insensitive_pattern(term: str) -> str:
    """Regex que casa `term` com ou sem acento, delimitado por word boundary."""
    body = "".join(
        f"[{ACCENT_CLASSES[ch]}]" if ch in ACCENT_CLASSES else re.escape(ch)
        for ch in _strip_accents(term).lower()
    )
    return rf"\b{body}\b"


def _new_token(kind: str) -> str:
    return f"[{kind}_{secrets.token_hex(2)}]"


class Pseudonymizer:
    """Mapa de tokens de uma sessão + as operações de ida e volta.

    O mapa CRESCE durante o `scrub` (telefone/CPF/e-mail achados no texto livre
    viram entradas novas), então quem usa deve persistir `.tokens` DEPOIS de
    mascarar tudo, não antes.
    """

    def __init__(self, tokens: dict[str, str] | None = None) -> None:
        # token -> valor real
        self.tokens: dict[str, str] = dict(tokens or {})
        # valor real (casefold) -> token, para reaproveitar o mesmo token quando o
        # mesmo telefone aparece em três respostas diferentes
        self._by_value: dict[str, str] = {
            v.casefold(): k for k, v in self.tokens.items()
        }
        # [(regex compilado, token)] ordenado por comprimento do termo, maior
        # primeiro — o nome completo tem que casar antes do primeiro nome, senão
        # "João da Silva" viraria "[PACIENTE_x] da Silva".
        self._rules: list[tuple[re.Pattern[str], str]] = []

    # ---- construção ----

    def add_identifier(self, kind: str, value: str | None) -> str | None:
        """Registra um identificador conhecido e devolve seu token.

        `kind` é o prefixo do token (PACIENTE, CLINICA, ...). Valor repetido
        reaproveita o token já emitido.
        """
        if not value or not isinstance(value, str):
            return None
        value = value.strip()
        if len(value) < MIN_TERM_LEN:
            return None
        existing = self._by_value.get(value.casefold())
        if existing:
            return existing
        token = _new_token(kind)
        self.tokens[token] = value
        self._by_value[value.casefold()] = token
        return token

    def add_person_name(self, kind: str, full_name: str | None) -> str | None:
        """Registra um nome completo E cada parte relevante dele.

        As partes apontam para o MESMO token do nome completo: o paciente que
        escreve "João" numa resposta e "João da Silva" em outra tem de virar o
        mesmo `[PACIENTE_x]`, senão a re-hidratação devolve nomes diferentes.
        """
        token = self.add_identifier(kind, full_name)
        if token is None:
            return None
        assert full_name is not None
        for part in full_name.split():
            part = part.strip(".,;:")
            if len(part) < MIN_TERM_LEN or part.casefold() in NAME_STOPWORDS:
                continue
            self._by_value.setdefault(part.casefold(), token)
        return token

    def _compile(self) -> list[tuple[re.Pattern[str], str]]:
        if not self._rules:
            self._rules = [
                (re.compile(_accent_insensitive_pattern(value), re.IGNORECASE), token)
                for value, token in sorted(
                    self._by_value.items(), key=lambda kv: len(kv[0]), reverse=True
                )
            ]
        return self._rules

    # ---- ida ----

    def scrub(self, value: Any) -> Any:
        """Mascara recursivamente str/dict/list. Outros tipos passam intactos."""
        if isinstance(value, str):
            return self._scrub_text(value)
        if isinstance(value, dict):
            return {k: self.scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub(v) for v in value]
        return value

    def _scrub_text(self, text: str) -> str:
        if not text:
            return text
        # Padrões ANTES dos nomes: se o nome rodasse primeiro, "joao@teste.com"
        # viraria "[PACIENTE_x]@teste.com" e o domínio vazaria. Os padrões
        # descobertos viram tokens novos (e invalidam o cache de regras).
        # A ordem entre os próprios padrões é invariante e vive em
        # `br_rules.PATTERN_RULES` — não reordene aqui.
        for pattern, kind in PATTERN_RULES:
            text = self._scrub_pattern(text, pattern, kind)
        for pattern, token in self._compile():
            text = pattern.sub(token, text)
        return text

    def _scrub_pattern(self, text: str, pattern: re.Pattern[str], kind: str) -> str:
        def replace(match: re.Match[str]) -> str:
            raw = match.group(0)
            token = self._by_value.get(raw.casefold())
            if token is None:
                token = _new_token(kind)
                self.tokens[token] = raw
                self._by_value[raw.casefold()] = token
                self._rules = []  # mapa mudou; recompila na próxima chamada
            return token

        return pattern.sub(replace, text)

    # ---- volta ----

    def rehydrate(self, value: Any) -> Any:
        """Devolve os valores reais no lugar dos tokens, recursivamente."""
        if isinstance(value, str):
            return self._rehydrate_text(value)
        if isinstance(value, dict):
            return {k: self.rehydrate(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.rehydrate(v) for v in value]
        return value

    def _rehydrate_text(self, text: str) -> str:
        if not text or "[" not in text:
            return text

        def replace(match: re.Match[str]) -> str:
            # A IA pode devolver o token com caixa trocada; o mapa é canônico.
            token = match.group(0)
            return self.tokens.get(token) or self.tokens.get(token.upper()) or token

        return _TOKEN_RE.sub(replace, text)


def has_unresolved_tokens(value: Any) -> bool:
    """True se sobrou token no payload — sinal de re-hidratação incompleta.

    Um token que escapa daqui chega ao consumidor final como "[PACIENTE_a7f3]" na
    cara do usuário, então quem chama deve LOGAR ALTO em vez de seguir em silêncio.
    """
    if isinstance(value, str):
        return bool(_TOKEN_RE.search(value))
    if isinstance(value, dict):
        return any(has_unresolved_tokens(v) for v in value.values())
    if isinstance(value, list):
        return any(has_unresolved_tokens(v) for v in value)
    return False
