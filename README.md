# pseudonymize-core

Small, stateless, **reversible** PII pseudonymization library shared by Brain Co
services. It replaces direct identifiers (person name, clinic name, phone, CPF,
e-mail) with reversible tokens *before* material leaves the country for a foreign
AI API, and rehydrates those tokens with the real values on the way back, inside
our own infrastructure.

```
outbound payload  ──► scrub      ──► [PACIENTE_a7f3] goes into the prompt
AI response       ──► rehydrate  ──► "João da Silva" comes back before persisting
```

## Design constraints

- **Stateless.** No database access, no disk writes, no network calls, no
  environment variable reads, no logging. The library only transforms text.
- **Pure stdlib.** Zero runtime dependencies (`re`, `secrets`, `unicodedata`).
  Python 3.12+.
- **Every substitution is reversible.** Masked text is read by *humans* after
  rehydration, not only by a model — irreversible masking (a fixed `[TELEFONE]`)
  would destroy legitimate data. Each discovered value gets its own token.
  (`redact_patterns` is the deliberate exception, for calls whose output never
  becomes persisted text.)
- **A token is never a hash of the value.** Hashed proper names fall to a
  dictionary attack in minutes; the suffix is random (`secrets`), unrelated to
  the content.
- **The caller owns the token map.** `Pseudonymizer.tokens` lives in memory;
  persisting it, scoping it, and deleting it afterwards is the caller's job.

> ⚠️ This is **pseudonymization, not anonymization**. Pseudonymized data is still
> personal data (LGPD art. 13, §4º) — the caller holds the key. It is a
> security/minimization measure (art. 46); it does **not** replace the
> international-transfer mechanism (art. 33) nor specific consent.

## Layout

| Module | Scope |
| --- | --- |
| `engine.py` | Generic mechanism: token issuing, the token↔value map, ordered substitution, recursion over `str`/`dict`/`list`, rehydration. |
| `br_rules.py` | Brazil-specific detection: CPF / phone (DDD, +55, ninth digit) / e-mail regexes, Portuguese name particles, accent classes, and `redact_patterns`. |

The split is deliberate: everything in `br_rules.py` is compliance fine-tuning
that would change outside Brazil, and is the part that would *not* ship if only
the engine were ever published.

## Install

```bash
uv add pseudonymize-core
```

Or as a git dependency, pinned by tag:

```toml
# pyproject.toml
[tool.uv.sources]
pseudonymize-core = { git = "https://github.com/MateusChrysostomoS/pseudonymize-core.git", tag = "v0.1.0" }
```

```
# requirements.txt
pseudonymize-core @ git+https://github.com/MateusChrysostomoS/pseudonymize-core.git@v0.1.0
```

## Usage

### Reversible (the normal path)

```python
from pseudonymize_core import Pseudonymizer, has_unresolved_tokens

p = Pseudonymizer()
p.add_person_name("PACIENTE", "João da Silva")   # registers the full name AND its parts
p.add_identifier("CLINICA", "Clínica Mangaratiba")

masked = p.scrub({"resumo": "João da Silva, tel (21) 99999-8888"})
# {'resumo': '[PACIENTE_5c34], tel [TELEFONE_18d0]'}

# The map GROWS during scrub (phones/CPFs/e-mails found in free text become new
# entries), so persist p.tokens AFTER masking everything, never before.
persist(p.tokens)

# ...later, with the AI's answer:
restored = Pseudonymizer(load_tokens()).rehydrate(ai_response)
if has_unresolved_tokens(restored):
    log.error("rehydration incomplete")  # a leaked token reaches the end user raw
```

### Irreversible (when the output never becomes persisted text)

```python
from pseudonymize_core import redact_patterns

redact_patterns("cpf 123.456.789-00, tel (21) 99999-8888")
# 'cpf [CPF omitido], tel [telefone omitido]'
```

Use this only where the result is a label or a classification, never where the
text has to be rehydrated.

## Behavior notes

- `add_person_name` maps every part of a name to the **same** token: a person who
  writes "João" in one answer and "João da Silva" in another must collapse to one
  `[PACIENTE_x]`, otherwise rehydration returns two different names.
- Substitution rules are applied longest-term-first, so the full name matches
  before the first name.
- Matching is accent- and case-insensitive, and always `\b`-delimited: `"Ana"`
  does not eat the `ana` inside `anamnese`.
- Terms shorter than 3 characters and Portuguese name particles (`de`, `da`,
  `dos`, …) never become substitution rules.
- Pattern order (e-mail → phone → CPF, all before names) is an **invariant**, not
  style — it lives in `br_rules.PATTERN_RULES`. Reordering leaks an e-mail domain
  or mislabels an unmasked mobile number as a CPF.

## Development

```bash
uv sync
uv run python -m pytest -q
```

No network access, no API keys, no database — the tests exercise pure functions.
