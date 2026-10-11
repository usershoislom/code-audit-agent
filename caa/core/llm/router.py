"""Model routing. Every request picks a provider by role and is written to the audit log.

A tag still travels with each request so the audit trail records what kind of material a call
carried, but it no longer restricts which provider is used: the operator analyses their own code
and their own sites, and the models they configure (local or their own hosted servers) are theirs
to send it to. Secrets are still masked before anything leaves the process (see core.audit and the
triage prompt builders); routing just records, it does not gate.
"""
from __future__ import annotations

from enum import Enum

from caa.core.audit import NULL_AUDIT, AuditLog
from caa.core.llm.provider import ChatModel


class Confidentiality(str, Enum):
    TARGET_PRIVATE = "target_private"   # kept for the audit label; no longer implies local-only
    OWN_STAND = "own_stand"
    OFFLINE_JUDGE = "offline_judge"


class ConfidentialityViolation(PermissionError):
    """Retained for import compatibility; no longer raised."""


class ModelRouter:
    def __init__(self, models: dict[str, ChatModel], roles: dict[str, str], audit: AuditLog = NULL_AUDIT):
        """models: name -> model; roles: role ("analysis", "judge", ...) -> preferred model name."""
        self.models = models
        self.roles = roles
        self.audit = audit

    def for_task(self, role: str, tag: Confidentiality) -> ChatModel:
        name = self.roles.get(role) or self.roles.get("analysis")
        model = self.models.get(name) if name else None
        if model is None:
            raise LookupError(f"no model configured for role {role!r}")
        self.audit.write("routing", role=role, tag=tag.value, used=model.config.name, local=model.config.is_local)
        return model


class _Lazy:
    """Defers client creation (and model auto-discovery) until a provider is actually routed to."""

    def __init__(self, config, audit):
        self.config, self._audit, self._m = config, audit, None

    def _get(self):
        if self._m is None:
            from caa.core.llm.provider import OpenAICompatibleModel
            self._m = OpenAICompatibleModel(self.config, audit=self._audit)
        return self._m

    @property
    def usage(self):
        return self._m.usage if self._m else {}

    def complete_json(self, messages, schema, purpose):
        return self._get().complete_json(messages, schema, purpose)

    def embed(self, texts):
        return self._get().embed(texts)


def build_router(cfg: dict, audit: AuditLog = NULL_AUDIT) -> ModelRouter | None:
    """cfg: parsed configs/providers.yaml."""
    from caa.core.llm.provider import ProviderConfig

    provs = cfg.get("providers") or {}
    own = cfg.get("self_hosted") or []
    models = {}
    for name, p in provs.items():
        models[name] = _Lazy(ProviderConfig(name=name, self_hosted=own, **p), audit)
    if not models:
        return None
    return ModelRouter(models, cfg.get("roles") or {"analysis": next(iter(models))}, audit)
