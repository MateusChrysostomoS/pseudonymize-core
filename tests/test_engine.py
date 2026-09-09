"""Testes do motor de pseudonimização.

Portados de `PreCheck/tests/test_pseudonymize.py` (camada pura, sem banco). Os
testes que exercitam a persistência do mapa de tokens ficaram no PreCheck, onde
vive o adaptador de banco (`app/services/pii_store.py`).

O teste que mais importa é o de round-trip: o que o humano lê no final tem de ser
byte-idêntico ao que seria sem a feature.
"""

from pseudonymize_core import Pseudonymizer, has_unresolved_tokens, redact_patterns


def test_nome_completo_e_primeiro_nome_viram_o_mesmo_token():
    p = Pseudonymizer()
    token = p.add_person_name("PACIENTE", "João da Silva")

    out = p.scrub("Paciente João da Silva relata dor. João nega febre.")

    assert "João" not in out
    assert "Silva" not in out
    assert out.count(token) == 2, "nome completo e primeiro nome têm de colapsar no mesmo token"


def test_nome_curto_nao_destroi_palavra_clinica():
    """'Ana' dentro de 'anamnese' é a armadilha nº 1 do checkpoint (§7.1)."""
    p = Pseudonymizer()
    p.add_person_name("PACIENTE", "Ana Paula")

    out = p.scrub("Na anamnese, Ana relata ananás e anasarca.")

    assert "anamnese" in out
    assert "ananás" in out
    assert "anasarca" in out
    assert "Ana relata" not in out


def test_particula_de_nome_nao_vira_regra():
    p = Pseudonymizer()
    p.add_person_name("PACIENTE", "Maria dos Santos")

    out = p.scrub("Vem dos exames de rotina e da consulta anterior.")

    assert out == "Vem dos exames de rotina e da consulta anterior."


def test_acento_e_caixa_sao_ignorados_na_busca():
    p = Pseudonymizer()
    token = p.add_person_name("PACIENTE", "João")

    assert p.scrub("joao chegou") == f"{token} chegou"
    assert p.scrub("JOÃO chegou") == f"{token} chegou"


def test_espaco_duplo_ou_tab_no_texto_nao_escapa_da_mascara():
    """Valor registrado vem canônico; o texto de origem é livre e pode ter
    espaçamento sujo (copy-paste, WhatsApp) — isso não pode fazer o nome vazar."""
    p = Pseudonymizer()
    token = p.add_identifier("PACIENTE", "João da Silva")

    assert p.scrub("Paciente João  da  Silva relata dor.") == f"Paciente {token} relata dor."
    assert p.scrub("Paciente João\tda Silva relata dor.") == f"Paciente {token} relata dor."


def test_telefone_cpf_email_viram_tokens_reversiveis():
    p = Pseudonymizer()

    texto = "Contato (21) 99999-8888, CPF 123.456.789-00, e-mail joao@teste.com.br"
    out = p.scrub(texto)

    assert "99999" not in out
    assert "123.456.789-00" not in out
    assert "joao@teste.com.br" not in out
    # e voltam exatamente como eram — o texto mascarado é lido por humanos
    assert p.rehydrate(out) == texto


def test_valor_repetido_reaproveita_o_mesmo_token():
    p = Pseudonymizer()
    out = p.scrub("ligar (21) 99999-8888 ou (21) 99999-8888")
    tokens = {t for t in out.split() if t.startswith("[")}
    assert len(tokens) == 1


def test_round_trip_preserva_estrutura_aninhada():
    p = Pseudonymizer()
    p.add_person_name("PACIENTE", "Carlos Eduardo Souza")
    p.add_identifier("CLINICA", "Clínica Mangaratiba")

    original = {
        "resumo": "Carlos Eduardo Souza, atendido na Clínica Mangaratiba.",
        "blocos": [
            {"pergunta": "Nome?", "resposta": "Carlos Eduardo Souza"},
            {"pergunta": "Idade?", "resposta": "42 anos"},
        ],
        "n_respostas": 2,
        "vazio": None,
    }

    scrubbed = p.scrub(original)

    assert "Carlos" not in str(scrubbed)
    assert "Mangaratiba" not in str(scrubbed)
    assert scrubbed["n_respostas"] == 2, "não-strings passam intactos"
    assert scrubbed["vazio"] is None
    assert p.rehydrate(scrubbed) == original


def test_idade_e_dado_clinico_sobrevivem():
    p = Pseudonymizer()
    p.add_person_name("PACIENTE", "Ana Paula")

    out = p.scrub("42 anos, PA 120/80, dor há 3 dias, 15/03 piorou")

    assert out == "42 anos, PA 120/80, dor há 3 dias, 15/03 piorou"


def test_has_unresolved_tokens():
    assert has_unresolved_tokens({"a": ["texto [PACIENTE_a7f3] aqui"]})
    assert not has_unresolved_tokens({"a": ["texto limpo"], "b": 3})


# ---- ordem padrões → nome, e o mascaramento irreversível ----


def test_email_com_nome_dentro_sai_inteiro():
    """Se o nome rodasse antes do e-mail, 'joao@teste.com' viraria
    '[PACIENTE_x]@teste.com' e o domínio vazaria."""
    p = Pseudonymizer()
    p.add_person_name("PACIENTE", "João da Silva")

    out = p.scrub("meu e-mail é joao@teste.com.br")

    assert "@teste" not in out
    assert "[EMAIL_" in out
    assert p.rehydrate(out) == "meu e-mail é joao@teste.com.br"


def test_celular_sem_mascara_vira_token_de_telefone_nao_de_cpf():
    p = Pseudonymizer()
    out = p.scrub("liga 21999998888")
    assert "[TELEFONE_" in out and "[CPF_" not in out


def test_redact_patterns_e_irreversivel_e_preserva_o_resto():
    out = redact_patterns("sim, tenho 42 anos, cpf 123.456.789-00, tel (21) 99999-8888")

    assert out == "sim, tenho 42 anos, cpf [CPF omitido], tel [telefone omitido]"
    assert redact_patterns("") == ""
