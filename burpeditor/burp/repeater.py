"""Repeater tabs.

Application root field 2 holds the Repeater state:
  1 list of tabs, 2 next tab number, 4 list of tab groups.

Every tab has 0 name, 1 index of the send shown in the tab (-1 for none),
32 group, and its record type tells what it is: 0 HTTP, 1 WebSocket.
HTTP tabs also have 2 list of sends (the tab's < > history), 3 service,
4/5 request in the editor (bytes, HTTP/2 header list), 9 notes.

Each send has 0 service, 2/10 request (bytes, HTTP/2 header list),
3 response, 4 time, 5 duration in ms, 7 status.

A new HTTP tab is laid out like the empty tab "1" Burp puts in new
projects (type 0, version 2):
  127 live marker, 0 name (chunked string), 1 current send, 32 group,
  2 sends, 3 service, 4/5 request, 6 flag, 7 tab options, 8 flag,
  9 notes (pooled text), 10 record holding an empty list,
  11 record holding -1, 33 tab id (two u64, a random UUID).
The tab options (7) are all zero except 11, set to 600000.
Field 2 of the Repeater state counts the tabs Burp named itself: it is 1
with the default tab "1", and the next unnamed tab is "2".
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from burpeditor.burp import http
from burpeditor.burp.services import Service, intern_service, request_service
from burpeditor.burp.store import Field, Record, Store

ROOT_REPEATER = 2
HTTP_TAB, WEBSOCKET_TAB = 0, 1
TAB_MARKER = 0x15E3AB60
TAB_VERSION = 2

# Field ids and sizes of an HTTP tab and its options, in Burp's descriptor order.
_TAB_LAYOUT = [
  (127, 4), (0, 8), (1, 4), (32, 8), (2, 8), (3, 8), (4, 8), (5, 8), (6, 1), (7, 8),
  (8, 1), (9, 8), (10, 8), (11, 8), (33, 8),
]
_TAB_OPTIONS_LAYOUT = [
  (0, 1), (1, 1), (2, 4), (3, 1), (4, 1), (5, 1), (6, 1), (7, 1), (8, 1), (9, 1), (10, 8), (11, 4),
]
# Burp's default for field 11 of the tab options, whose meaning is unknown.
_TAB_OPTION_11 = 600000


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

  def add(self, request: bytes, name: Optional[str] = None, service: Optional[Service] = None,
          secure: bool = True, notes: Optional[str] = None) -> str:
    """Add an HTTP tab with `request` in its editor and no sends; return its name.

    The target service comes from the Host header (or an absolute request
    target) unless `service` is given. Without `name` the tab is numbered
    the way Burp numbers new tabs.
    """
    http.validate_request(request)
    request = http.normalize(request, is_request=True)

    if service is None:
      _, service = request_service(request, secure=secure)

    state = self._state

    if name is None:
      number = state.u32(2) + 1
      name = str(number)
      state.set_u32(2, number)

    tab_id = uuid.uuid4().int
    values = {
      127: TAB_MARKER, 1: -1,
      0: self._store.new_string_n(name),
      2: self._store.new_list(),
      3: intern_service(self._store, self._root, service),
      4: self._store.new_array(request),
      7: self._store.new_record([Field(fid, size, _TAB_OPTION_11 if fid == 11 else 0)
                                 for fid, size in _TAB_OPTIONS_LAYOUT]),
      9: self._store.new_text(notes),
      10: self._store.new_record([Field(0, 8, self._store.new_list())]),
      11: self._store.new_record([Field(0, 4, -1)]),
      33: self._store.new_record([Field(0, 8, tab_id >> 64), Field(1, 8, tab_id & (2**64 - 1))]),
    }

    ptr = self._store.new_record([Field(fid, size, values.get(fid, 0)) for fid, size in _TAB_LAYOUT],
                                 type_id=HTTP_TAB, version=TAB_VERSION)
    self._store.list_append(state.ref(1), ptr)

    return name

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
