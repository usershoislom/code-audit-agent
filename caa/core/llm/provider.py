"""Model abstraction: one OpenAI-compatible interface for local and hosted models.

Structured output is mandatory: every call names a pydantic schema; the
provider asks the server for JSON-schema constrained output (Ollama,
llama.cpp and Groq all accept `response_format`), validates the reply, retries
with a reminder, and finally returns None ("insufficient data").
"""
from __future__ import annotations

import json
import os
import time
from ipaddress import ip_address
from typing import Protocol, TypeVar
from urllib.parse import urlparse

from pydantic import BaseModel, Field, ValidationError, computed_field

from caa.core.audit import NULL_AUDIT, AuditLog

T = TypeVar("T", bound=BaseModel)
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}


class ProviderConfig(BaseModel):
    name: str
    provider: str = "openai_compatible"
    model: str
    base_url: str
    api_key_env: str | None = None
    structured_output: str = "json_schema"      # json_schema | json_object
    temperature: float = 0.0
    seed: int | None = 0
    max_tokens: int = 2048
    timeout_s: float = 300.0
    extra_body: dict = Field(default_factory=dict)   # e.g. {"options": {"num_ctx": 32768}} for Ollama
    embedding_model: str | None = None

    @computed_field  # derived from the URL, never from a user-supplied flag
    @property
    def is_local(self) -> bool:
        host = (urlparse(self.base_url).hostname or "").lower()
        if host in LOCAL_HOSTS:
            return True
        try:
            return ip_address(host).is_loopback
        except ValueError:
            return False


class ChatModel(Protocol):
    config: ProviderConfig

    def complete_json(self, messages: list[dict], schema: type[T], purpose: str) -> T | None: ...

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class OpenAICompatibleModel:
    def __init__(self, config: ProviderConfig, audit: AuditLog = NULL_AUDIT, max_retries: int = 2):
        from openai import OpenAI  # imported lazily: the tool runs without the SDK in --no-llm mode

        self.config = config
        self.audit = audit
        self.max_retries = max_retries
        key = os.environ.get(config.api_key_env, "") if config.api_key_env else ""
        self.client = OpenAI(base_url=config.base_url, api_key=key or "not-needed", timeout=config.timeout_s)
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0}
        if config.model == "auto":      # servers that host one model: take it from /models
            self.config = config.model_copy(update={"model": self.client.models.list().data[0].id})

    def _response_format(self, schema: type[BaseModel]) -> dict:
        if self.config.structured_output == "json_schema":
            return {"type": "json_schema",
                    "json_schema": {"name": schema.__name__, "schema": schema.model_json_schema(), "strict": False}}
        return {"type": "json_object"}

    def complete_json(self, messages: list[dict], schema: type[T], purpose: str) -> T | None:
        msgs = list(messages)
        for attempt in range(self.max_retries + 1):
            t0 = time.time()
            try:
                resp = self.client.chat.completions.create(
                    model=self.config.model, messages=msgs, temperature=self.config.temperature,
                    seed=self.config.seed, max_tokens=self.config.max_tokens,
                    response_format=self._response_format(schema), extra_body=self.config.extra_body or None)
            except Exception as exc:  # network / server error: logged, treated as invalid output
                self.audit.write("llm_error", purpose=purpose, provider=self.config.name, error=str(exc)[:500])
                return None
            text = resp.choices[0].message.content or ""
            if resp.usage:
                self.usage["prompt_tokens"] += resp.usage.prompt_tokens or 0
                self.usage["completion_tokens"] += resp.usage.completion_tokens or 0
            self.usage["calls"] += 1
            self.audit.write("llm_call", purpose=purpose, provider=self.config.name, model=self.config.model,
                             attempt=attempt, seconds=round(time.time() - t0, 2), output=text[:4000])
            parsed = parse_json_reply(text, schema)
            if parsed is not None:
                return parsed
            msgs = msgs + [{"role": "assistant", "content": text},
                           {"role": "user", "content": "Your reply was not valid JSON for the required schema. "
                            "Reply again with ONLY a JSON object matching this schema:\n"
                            + json.dumps(schema.model_json_schema())}]
        return None

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not self.config.embedding_model:
            raise RuntimeError("no embedding_model configured")
        resp = self.client.embeddings.create(model=self.config.embedding_model, input=texts)
        return [d.embedding for d in resp.data]


def parse_json_reply(text: str, schema: type[T]) -> T | None:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        return None
    try:
        return schema.model_validate(json.loads(text[start:end + 1]))
    except (json.JSONDecodeError, ValidationError):
        return None


class ScriptedModel:
    """Deterministic stand-in used ONLY by unit tests (never in evaluation numbers)."""

    def __init__(self, replies: list[str] | None = None, local: bool = True, responder=None):
        self.config = ProviderConfig(name="scripted", model="scripted",
                                     base_url="http://127.0.0.1:1/v1" if local else "https://api.example.invalid/v1")
        self.replies = list(replies or [])
        self.responder = responder
        self.calls: list[tuple[str, list[dict]]] = []
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0, "calls": 0}

    def complete_json(self, messages, schema, purpose):
        self.calls.append((purpose, messages))
        self.usage["calls"] += 1
        for _ in range(3):
            text = self.responder(purpose, messages) if self.responder else (self.replies.pop(0) if self.replies else "")
            parsed = parse_json_reply(text, schema)
            if parsed is not None:
                return parsed
            if not self.responder and not self.replies:
                break
        return None

    def embed(self, texts):
        raise RuntimeError("no embeddings")
