"""Tests for the Langfuse observability layer."""

from __future__ import annotations

import sys
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr

import nexus.observability.langfuse as langfuse_module
from nexus.observability.langfuse import (
    NullCallbackHandler,
    flush_langfuse,
    get_langfuse_handler,
    reset_langfuse_client_for_tests,
    start_span,
)
from nexus.settings import Settings


@pytest.fixture(autouse=True)
def _reset_module_state() -> None:
    """Ensure singleton caches do not leak across tests."""
    reset_langfuse_client_for_tests()


def _settings_with_creds(**overrides: Any) -> Settings:
    return Settings(
        openai_api_key=SecretStr("sk-test"),
        langfuse_public_key=SecretStr("pk-test"),
        langfuse_secret_key=SecretStr("sk-lf-test"),
        **overrides,
    )


def _settings_without_creds() -> Settings:
    return Settings(
        openai_api_key=SecretStr("sk-test"),
        langfuse_public_key=None,
        langfuse_secret_key=None,
    )


def _install_fake_langfuse_module() -> tuple[MagicMock, MagicMock]:
    """Inject a synthetic ``langfuse.langchain`` exposing a CallbackHandler.

    Returns the (CallbackHandler class, Langfuse client class) mocks so
    tests can assert how they were instantiated.
    """
    handler_cls = MagicMock(name="CallbackHandler")
    handler_cls.return_value = MagicMock(name="callback_handler_instance")

    client_cls = MagicMock(name="Langfuse")
    client_cls.return_value = MagicMock(name="langfuse_client")

    fake_langfuse = ModuleType("langfuse")
    fake_langfuse.Langfuse = client_cls  # type: ignore[attr-defined]
    fake_langchain = ModuleType("langfuse.langchain")
    fake_langchain.CallbackHandler = handler_cls  # type: ignore[attr-defined]

    sys.modules["langfuse"] = fake_langfuse
    sys.modules["langfuse.langchain"] = fake_langchain
    return handler_cls, client_cls


def _purge_fake_langfuse_module() -> None:
    sys.modules.pop("langfuse", None)
    sys.modules.pop("langfuse.langchain", None)


def test_returns_null_handler_when_credentials_missing() -> None:
    with patch.object(langfuse_module, "get_settings", return_value=_settings_without_creds()):
        handler = get_langfuse_handler("sess-1")

    assert isinstance(handler, NullCallbackHandler)


def test_returns_null_handler_when_package_import_fails() -> None:
    sys.modules.pop("langfuse", None)
    sys.modules.pop("langfuse.langchain", None)

    # Force the import to raise even if installed in the environment.
    original_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("langfuse"):
            raise ImportError(f"forced missing: {name}")
        return original_import(name, *args, **kwargs)

    with (
        patch.object(langfuse_module, "get_settings", return_value=_settings_with_creds()),
        patch("builtins.__import__", side_effect=fake_import),
    ):
        handler = get_langfuse_handler("sess-2")

    assert isinstance(handler, NullCallbackHandler)


def test_returns_callback_handler_when_credentials_set() -> None:
    handler_cls, client_cls = _install_fake_langfuse_module()
    try:
        with patch.object(
            langfuse_module,
            "get_settings",
            return_value=_settings_with_creds(),
        ):
            handler = get_langfuse_handler("sess-42")
    finally:
        _purge_fake_langfuse_module()

    assert handler is handler_cls.return_value
    assert handler.session_id == "sess-42"
    assert handler.trace_name == "nexus/session/sess-42"
    # Client built with credentials from Settings.
    client_cls.assert_called_once()
    kwargs = client_cls.call_args.kwargs
    assert kwargs["public_key"] == "pk-test"
    assert kwargs["secret_key"] == "sk-lf-test"


def test_null_callback_handler_does_not_raise_on_callbacks() -> None:
    handler = NullCallbackHandler()

    # Touch every LangChain callback hook a ChatOpenAI invocation cycles
    # through. None should raise.
    handler.on_llm_start({}, ["prompt"])
    handler.on_llm_end({"generations": []})
    handler.on_llm_error(RuntimeError("boom"))
    handler.on_chain_start({}, {})
    handler.on_chain_end({})
    handler.on_chain_error(RuntimeError("boom"))
    handler.on_tool_start({}, "input")
    handler.on_tool_end("output")
    handler.on_tool_error(RuntimeError("boom"))
    handler.flush()
    handler.shutdown()


def test_null_callback_handler_rejects_unknown_attribute() -> None:
    handler = NullCallbackHandler()
    with pytest.raises(AttributeError):
        handler.totally_not_a_callback_hook  # noqa: B018


def test_flush_langfuse_noop_without_credentials() -> None:
    with patch.object(langfuse_module, "get_settings", return_value=_settings_without_creds()):
        flush_langfuse()  # must not raise


def test_flush_langfuse_calls_client_flush_when_configured() -> None:
    _handler_cls, client_cls = _install_fake_langfuse_module()
    try:
        with patch.object(
            langfuse_module,
            "get_settings",
            return_value=_settings_with_creds(),
        ):
            # First call constructs the singleton, second exercises flush.
            get_langfuse_handler("sess-flush")
            flush_langfuse()
    finally:
        _purge_fake_langfuse_module()

    client_cls.return_value.flush.assert_called_once()


def test_flush_langfuse_swallows_client_errors() -> None:
    _handler_cls, client_cls = _install_fake_langfuse_module()
    client_cls.return_value.flush.side_effect = RuntimeError("network down")
    try:
        with patch.object(
            langfuse_module,
            "get_settings",
            return_value=_settings_with_creds(),
        ):
            get_langfuse_handler("sess-x")
            flush_langfuse()  # must not raise
    finally:
        _purge_fake_langfuse_module()


def test_start_span_yields_null_span_when_client_missing() -> None:
    with patch.object(langfuse_module, "get_settings", return_value=_settings_without_creds()):
        with start_span("nexus/test", session_id="sess-z", metadata={"k": 1}) as span:
            # NullSpan ``update`` is a no-op and must not raise.
            span.update(output={"ok": True})


def test_start_span_uses_real_client_when_available() -> None:
    _handler_cls, client_cls = _install_fake_langfuse_module()
    fake_span = MagicMock(name="span")
    span_cm = MagicMock(name="span_cm")
    span_cm.__enter__.return_value = fake_span
    span_cm.__exit__.return_value = False
    client_cls.return_value.start_as_current_span.return_value = span_cm
    try:
        with patch.object(
            langfuse_module,
            "get_settings",
            return_value=_settings_with_creds(),
        ):
            with start_span(
                "nexus/researcher",
                session_id="sess-span",
                metadata={"task_count": 4},
            ) as span:
                assert span is fake_span
                span.update(output={"findings_count": 7})
    finally:
        _purge_fake_langfuse_module()

    client_cls.return_value.start_as_current_span.assert_called_once_with(
        name="nexus/researcher",
    )
    # First ``update`` carries session/metadata; second carries the output.
    update_calls = fake_span.update.call_args_list
    assert update_calls[0].kwargs["session_id"] == "sess-span"
    assert update_calls[0].kwargs["metadata"] == {"task_count": 4}
    assert update_calls[-1].kwargs["output"] == {"findings_count": 7}
