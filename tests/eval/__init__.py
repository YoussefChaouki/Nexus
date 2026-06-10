"""NEXUS evaluation harness (Sprint 9, S9.T1).

Measures OWASP LLM Top 10 coverage and threat-surface coverage of the
full multi-agent pipeline, and compares it against a single-prompt
baseline. The harness runs either against a deterministic offline mock
(``use_real_llm=False`` — used in CI) or a live model
(``use_real_llm=True`` — used by ``scripts/compare_baseline.py`` to
produce the README metrics).
"""
