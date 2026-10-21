"""Repeater tabs.

Application root field 2 holds the Repeater state:
  1 list of tabs, 2 next tab number, 4 list of tab groups.

Every tab has 0 name, 1 index of the send shown in the tab (-1 for none),
32 group, and its record type tells what it is: 0 HTTP, 1 WebSocket.
HTTP tabs also have 2 list of sends (the tab's < > history), 3 service,
4/5 request in the editor (bytes, HTTP/2 header list), 9 notes.

Each send has 0 service, 2/10 request (bytes, HTTP/2 header list),
3 response, 4 time, 5 duration in ms, 7 status.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from burpeditor.burp import http
from burpeditor.burp.services import Service
from burpeditor.burp.store import Record, Store

ROOT_REPEATER = 2
HTTP_TAB, WEBSOCKET_TAB = 0, 1


@dataclass
class RepeaterSend:
  number: int
  service: Optional[Service]
  request: Optional[bytes]
  response: Optional[bytes]
  status: int
  time: Optional[datetime]
  duration_ms: int

  def to_dict(self) -> dict:
    return {
      "number": self.number, "status": self.status, "duration_ms": self.duration_ms,
      "time": self.time.isoformat() if self.time else None,
    }


@dataclass
class RepeaterTab:
  name: str
  kind: str
  group: Optional[str]
  service: Optional[Service]
  request: Optional[bytes]
  notes: Optional[str]
  current: int
  sends: list[RepeaterSend] = field(default_factory=list)

  @property
  def current_send(self) -> Optional[RepeaterSend]:
    """The send whose response the tab shows."""
    return self.sends[self.current] if 0 <= self.current < len(self.sends) else None

  @property
  def response(self) -> Optional[bytes]:
    send = self.current_send
    return send.response if send else None

  @property
  def url(self) -> str:
    if not self.request:
      return self.service.origin if self.service else ""

    try:
      target, _ = http.origin_form(http.request_line(self.request).target)
    except ValueError:
      target = ""

    return (self.service.origin if self.service else "") + target

  @property
  def method(self) -> Optional[str]:
    try:
      return http.request_line(self.request).method if self.request else None
    except ValueError:
      return None

  def to_dict(self) -> dict:
    return {
      "name": self.name, "kind": self.kind, "group": self.group, "method": self.method,
      "url": self.url, "notes": self.notes, "sends": [send.to_dict() for send in self.sends],
    }


class Repeater:
  def __init__(self, store: Store, root: Record) -> None:
    self._store = store
    self._root = root

  @property
  def _state(self) -> Record:
    return self._store.record(self._root.ref(ROOT_REPEATER))

  def tabs(self) -> list[RepeaterTab]:
    return [self._tab(rec) for rec in self._store.iter_records(self._state.list(1))]

  def get(self, name: str) -> RepeaterTab:
    matches = [tab for tab in self.tabs() if tab.name == name]

    if not matches:
      raise KeyError(f"Repeater tab {name!r} not found")

    if len(matches) > 1:
      raise KeyError(f"{len(matches)} Repeater tabs are named {name!r}")

    return matches[0]

  def _request(self, rec: Record, data: int, header_list: int) -> Optional[bytes]:
    headers = self._store.headers(rec.ref(header_list))

    if headers:
      return http.assemble_http2_request(headers, rec.array(data) or b"")

    return rec.array(data) or None

  def _tab(self, rec: Record) -> RepeaterTab:
    group = rec.record(32)
    tab = RepeaterTab(
      name=self._store.string_n(rec.ref(0)) or "",
      kind="HTTP" if rec.type_id == HTTP_TAB else "WebSocket",
      group=group.string(0) if group else None,
      service=None,
      request=None,
      notes=None,
      current=rec.i32(1),
    )

    if rec.type_id != HTTP_TAB:
      return tab

    tab.service = Service.from_record(rec.record(3))
    tab.request = self._request(rec, 4, 5)
    tab.notes = self._store.text(rec.ref(9)) or None
    tab.sends = [self._send(number, send) for number, send in
                 enumerate(self._store.iter_records(rec.list(2)), start=1)]
    return tab

  def _send(self, number: int, rec: Record) -> RepeaterSend:
    millis = rec.i64(4)
    return RepeaterSend(
      number=number,
      service=Service.from_record(rec.record(0)),
      request=self._request(rec, 2, 10),
      response=rec.array(3),
      status=rec.u16(7),
      time=datetime.fromtimestamp(millis / 1000, timezone.utc) if millis > 0 else None,
      duration_ms=rec.i64(5),
    )
