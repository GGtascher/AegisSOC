from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from sqlalchemy import select

from aegis.config import RULES_DIR
from aegis.database.models import RuleState

log = logging.getLogger(__name__)


@dataclass
class DetectionRule:
    id: str
    name: str
    category: str
    severity: str
    description: str = "Suspicious behavior detected."
    recommendation: str = "Review the process and related activity."
    enabled: bool = True
    process_name: str | None = None
    command_contains: list[str] = field(default_factory=list)
    event_type: str | None = None
    extensions: list[str] = field(default_factory=list)
    mitre: dict = field(default_factory=dict)

    def public(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "enabled": self.enabled,
            "mitre": self.mitre,
            "description": self.description,
        }


class RuleStore:
    def __init__(self, database, directory: Path | str = RULES_DIR):
        self.database = database
        self.directory = Path(directory)
        self.rules: dict[str, DetectionRule] = {}

    def load(self) -> list[DetectionRule]:
        loaded: dict[str, DetectionRule] = {}
        for path in sorted(self.directory.glob("*.yaml")):
            try:
                items = yaml.safe_load(path.read_text(encoding="utf-8")) or []
                for item in items:
                    rule = DetectionRule(**item)
                    loaded[rule.id] = rule
            except Exception:
                log.exception("Could not load rules from %s", path.name)
        with self.database.session() as session:
            states = {state.rule_id: state.enabled for state in session.scalars(select(RuleState))}
        for rule in loaded.values():
            if rule.id in states:
                rule.enabled = states[rule.id]
        self.rules = loaded
        log.info("Loaded %s detection rules", len(loaded))
        return list(loaded.values())

    def set_enabled(self, rule_id: str, enabled: bool) -> DetectionRule | None:
        rule = self.rules.get(rule_id)
        if rule is None:
            return None
        rule.enabled = enabled
        with self.database.session() as session:
            session.merge(RuleState(rule_id=rule_id, enabled=enabled))
        return rule
