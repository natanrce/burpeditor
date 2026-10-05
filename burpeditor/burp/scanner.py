"""Scanner data: tasks (Dashboard) and issues.

Application root field 7 holds the scanner state:
  1 list of tasks (polymorphic by record type), 2 resource pools,
  3 paged list of issue index entries.

Task fields: 1 task number, 2 source (e.g. "Proxy (all traffic)"),
3 configuration summary, 4 paused, 8 custom name.

Issue index entry: 2 time, 5 issue, 6 task number. Issue fields: 0 serial
number, 1 service, 3 path, 6 severity, 7 confidence, 8/9 user overrides of
severity/confidence, 12 evidence list, 15 issue type.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from importlib import resources
from typing import Optional

from burpeditor.burp.services import Service
from burpeditor.burp.store import Record, Store

ROOT_SCANNER = 7

TASK_TYPES = {
  2: "Crawl and audit",
  3: "Extension driven passive scan",
  4: "Live passive crawl",
  5: "Live audit",
  6: "Intruder attack",
  7: "API scan",
}
class Severity(Enum):
  """Issue severity; values are the bytes Burp stores, members are in severity order."""
  HIGH = 4
  MEDIUM = 3
  LOW = 2
  INFORMATION = 1
  FALSE_POSITIVE = 0xFF

  @property
  def label(self) -> str:
    return self.name.replace("_", " ").capitalize()

  @property
  def rank(self) -> int:
    """0 for the most severe."""
    return list(Severity).index(self)

  @classmethod
  def from_byte(cls, value: int) -> Optional["Severity"]:
    try:
      return cls(value)
    except ValueError:
      return None

CONFIDENCES = {1: "Tentative", 2: "Firm", 3: "Certain"}

_issue_types: Optional[dict[str, dict]] = None

def issue_type_name(type_index: int) -> str:
  global _issue_types

  if _issue_types is None:
    data = resources.files("burpeditor.burp").joinpath("data/issue_types.json").read_text()
    _issue_types = json.loads(data)

  entry = _issue_types.get(str(type_index))
  return entry["name"] if entry else f"Unknown issue type 0x{type_index:08x}"


@dataclass
class Task:
  number: int
  type: int
  source: str
  configuration: str
  name: Optional[str]
  paused: bool

  @property
  def label(self) -> str:
    kind = TASK_TYPES.get(self.type, f"Task type {self.type}")
    label = f"{self.number}. {kind}"

    if self.source:
      label += f" from {self.source}"

    if self.name:
      label += f": {self.name}"

    return label

@dataclass
class Evidence:
  request: Optional[bytes]
  response: Optional[bytes]

  def to_dict(self) -> dict:
    return {"request": (self.request or b"").decode("latin-1"),
            "response": (self.response or b"").decode("latin-1")}

@dataclass
class Issue:
  serial: int
  type_index: int
  name: str
  severity: Optional[Severity]
  confidence: str
  service: Optional[Service]
  path: str
  task: int
  time: Optional[datetime]
  evidence: list[Evidence] = field(default_factory=list)

  @property
  def url(self) -> str:
    return (self.service.origin if self.service else "") + self.path

  def to_dict(self, evidence: bool = False) -> dict:
    """JSON-ready values; evidence messages are included only on request, else counted."""
    return {
      "serial": self.serial, "type": self.type_index, "name": self.name,
      "severity": self.severity.label if self.severity else None, "confidence": self.confidence, "url": self.url,
      "task": self.task, "time": self.time.isoformat() if self.time else None,
      "evidence": [e.to_dict() for e in self.evidence] if evidence else len(self.evidence),
    }

class Scanner:
  def __init__(self, store: Store, root: Record) -> None:
    self._store = store
    self._root = root

  @property
  def _state(self) -> Record:
    return self._store.record(self._root.ref(ROOT_SCANNER))

  def tasks(self) -> list[Task]:
    tasks = []

    for rec in self._store.iter_records(self._state.list(1)):
      tasks.append(Task(
        number=rec.u32(1),
        type=rec.type_id,
        source=self._store.string_n(rec.ref(2)) or "",
        configuration=self._store.string_n(rec.ref(3)) or "",
        name=(rec.string(8) or "").strip() or None,
        paused=rec.bool(4),
      ))

    return tasks

  def issues(self) -> list[Issue]:
    issues = []

    for entry in self._store.iter_records(self._state.list(3)):
      rec = entry.record(5)

      if rec is None:
        continue

      severity = rec.u8(8) or rec.u8(6)
      confidence = rec.u8(9) or rec.u8(7)
      millis = entry.i64(2)
      issues.append(Issue(
        serial=rec.u64(0),
        type_index=rec.u32(15),
        name=issue_type_name(rec.u32(15)),
        severity=Severity.from_byte(severity),
        confidence=CONFIDENCES.get(confidence, str(confidence)),
        service=Service.from_record(rec.record(1)),
        path=rec.string(3) or (rec.array(2) or b"").decode("latin-1"),
        task=entry.u32(6),
        time=datetime.fromtimestamp(millis / 1000, timezone.utc) if millis > 0 else None,
        evidence=self._evidence(rec),
      ))
    return issues

  def _evidence(self, issue: Record) -> list[Evidence]:
    evidence = []

    for item in self._store.iter_records(issue.list(12)):
      # Request/response pairs: 0 service, 1 URL, 2 request, 3 response.
      for field_id in (33, 34, 35):
        pair = item.record(field_id) if field_id in item else None

        if pair is not None and 2 in pair and 3 in pair and 0 in pair:
          evidence.append(Evidence(pair.array(2), pair.array(3)))

    return evidence

