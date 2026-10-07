"""Confidentiality routing. Enforced in code, not left to configuration discipline.

Every model request carries a tag:
* TARGET_PRIVATE  - material from a system that is not ours (code or HTTP
                    responses of an analysed third-party target). LOCAL ONLY.
* OWN_STAND       - our own seeded / open training stand. Any provider.
* OFFLINE_JUDGE   - offline roles (teacher/judge) over our own stand data. Any provider.

The run's trust mode decides the tag for analysis calls; the default is the
safe one (third-party).
"""
from __future__ import annotations

from enum import Enum

from caa.core.audit import NULL_AUDIT, AuditLog
from caa.core.llm.provider import ChatModel


class Confidentiality(str, Enum):
    TARGET_PRIVATE = "target_private"
    OWN_STAND = "own_stand"
    OFFLINE_JUDGE = "offline_judge"


class ConfidentialityViolation(PermissionError):
    pass


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
        if tag == Confidentiality.TARGET_PRIVATE and not model.config.is_local:
            local = [m for m in self.models.values() if m.config.is_local]
            if not local:
                self.audit.write("routing_refused", role=role, tag=tag.value, wanted=model.config.name)
                raise ConfidentialityViolation(
                    f"role {role!r} is configured with non-local provider {model.config.name!r}; "
                    "third-party target data may only go to a local model and none is configured")
            self.audit.write("routing_rerouted", role=role, tag=tag.value, wanted=model.config.name,
                             used=local[0].config.name)
            model = local[0]
        self.audit.write("routing", role=role, tag=tag.value, used=model.config.name, local=model.config.is_local)
        return model


def build_router(cfg: dict, audit: AuditLog = NULL_AUDIT) -> ModelRouter | None:
    """cfg: parsed configs/providers.yaml."""
    from caa.core.llm.provider import OpenAICompatibleModel, ProviderConfig

    provs = cfg.get("providers") or {}
    models = {}
    for name, p in provs.items():
        models[name] = OpenAICompatibleModel(ProviderConfig(name=name, **p), audit=audit)
    if not models:
        return None
    return ModelRouter(models, cfg.get("roles") or {"analysis": next(iter(models))}, audit)
