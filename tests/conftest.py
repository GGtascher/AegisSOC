from __future__ import annotations

import pytest

from aegis.database.db import Database
from aegis.detection.baseline import BaselineStore
from aegis.detection.correlation import IncidentCorrelator
from aegis.detection.engine import DetectionEngine
from aegis.detection.rules import RuleStore


@pytest.fixture
def stack(tmp_path):
    database = Database(tmp_path / "test.db")
    database.initialize()
    rules = RuleStore(database)
    rules.load()
    correlator = IncidentCorrelator(database)
    engine = DetectionEngine(database, rules, correlator)
    return database, rules, BaselineStore(database), engine
