"""Proxy HTTP history.

Application root field 1 holds the history container:
  0 paged list of every HTTP item (the Proxy > HTTP history table)
  1 paged list of the items that passed the table's display filter when the
    project was saved, in table order; Burp uses it to show the filtered
    table on load before re-running the filter
  2, 3 the same pair for WebSocket messages
  4 last HTTP item number, 5 last WebSocket message number

Each HTTP item (record type 1) has, among others:
  127 live marker, 0 item number, 1 method, 2 request target, 3 extension,
  4 server IP, 5 has parameters, 6 status, 7 MIME code, 8 response length,
  9 page title, 10 Set-Cookie summary, 11 request time, 13 highlight,
  14 listener port, 15/16/17 original/auto-modified/edited request,
  18/19/20 original/auto-modified/edited response, 24/25/26 request protocols,
  27 comment, 28/29 durations, 30 response time.

Burp's message viewer offers the original, auto-modified (match and replace
rules) and edited (interceptor) versions; the "Edited" column reflects 17/20.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, Optional

from burpeditor.burp import http
from burpeditor.burp.services import Service, intern_service
from burpeditor.burp.store import Field, Record, Store

ROOT_HISTORY = 1
ALL_ITEMS = 0
FILTERED_ITEMS = 1
ITEM_TYPE = 1
LIVE_MARKER = 0x7A13353F
PROTOCOL_UNKNOWN = 0xFF
DEFAULT_LISTENER_PORT = 8080

# Field ids and sizes of a history item, in Burp's descriptor order.
_ITEM_LAYOUT = [
  (127, 4), (0, 4), (1, 8), (2, 8), (3, 8), (4, 8), (5, 1), (6, 2), (7, 2), (8, 4),
  (9, 8), (10, 8), (11, 8), (13, 1), (14, 4), (15, 8), (16, 8), (17, 8), (18, 8),
  (19, 8), (20, 8), (21, 8), (22, 8), (23, 8), (24, 1), (25, 1), (26, 1), (27, 8),
  (28, 8), (29, 8), (30, 8),
]
_REQUEST_SLOTS = (17, 16, 15)
_RESPONSE_SLOTS = (20, 19, 18)


@dataclass
class HistoryItem:
  number: int
  method: str
  service: Optional[Service]
  target: str
  ip: Optional[str]
  status: int
  mime: str
  length: int
  time: Optional[datetime]
  comment: Optional[str]
  edited: bool
  request: Optional[bytes]
  response: Optional[bytes]
  offset: int

  @property
  def url(self) -> str:
    origin = self.service.origin if self.service else ""
    return origin + self.target

  def to_dict(self) -> dict:
    """The item's metadata as JSON-ready values (messages excluded)."""
    return {
      "number": self.number, "method": self.method, "url": self.url, "status": self.status,
      "length": self.length, "mime": self.mime, "ip": self.ip, "edited": self.edited,
      "comment": self.comment, "time": self.time.isoformat() if self.time else None,
    }


class HTTPHistory:
  def __init__(self, store: Store, root: Record) -> None:
    self._store = store
    self._root = root

  @property
  def _container(self) -> Record:
    return self._store.record(self._root.ref(ROOT_HISTORY))

  def _records(self) -> Iterator[Record]:
    for rec in self._store.iter_records(self._container.list(ALL_ITEMS)):
      if rec.u32(127) == LIVE_MARKER:
        yield rec

  def __iter__(self) -> Iterator[HistoryItem]:
    return (self._item(rec) for rec in self._records())

  def __len__(self) -> int:
    return sum(1 for _ in self._records())

  def get(self, number: int) -> HistoryItem:
    return self._item(self._find(number))

  def _find(self, number: int) -> Record:
    for rec in self._records():
      if rec.u32(0) == number:
        return rec
    raise KeyError(f"history item #{number} not found")

  def _message(self, rec: Record, slots: tuple[int, ...]) -> Optional[bytes]:
    for slot in slots:
      if rec.ref(slot):
        return rec.array(slot)
    return None

  def _item(self, rec: Record) -> HistoryItem:
    key = rec.record(2)
    timestamp = rec.i64(11)

    return HistoryItem(
      number=rec.u32(0),
      method=rec.string(1) or "",
      service=Service.from_record(key.record(0)) if key else None,
      target=(key.array(1) or b"").decode("latin-1") if key else "",
      ip=rec.string(4),
      status=rec.u16(6),
      mime=http.MIME_NAMES.get(rec.u16(7), ""),
      length=rec.u32(8),
      time=datetime.fromtimestamp(timestamp / 1000, timezone.utc) if timestamp > 0 else None,
      comment=self._store.text(rec.ref(27)) or None,
      edited=bool(rec.ref(17) or rec.ref(20)),
      request=self._message(rec, _REQUEST_SLOTS),
      response=self._message(rec, _RESPONSE_SLOTS),
      offset=rec.offset,
    )

  def _url_key(self, service_ptr: int, target: str) -> int:
    raw = target.encode("latin-1")
    query = raw.find(b"?")
    ptr = self._store.new_record([Field(0, 8, service_ptr), Field(1, 8), Field(2, 4, query),
                                  Field(3, 4, len(raw) if query >= 0 else -1), Field(4, 8), Field(5, 4)])
    self._store.write_u64(ptr + 30, self._store.new_array(raw))
    
    return ptr

  def _set_string(self, rec: Record, field_id: int, value: Optional[str]) -> None:
    rec.set_u64(field_id, self._store.new_string(value) if value is not None else 0)

  def _target_service(self, raw: bytes, current: Optional[Service]) -> tuple[str, Service]:
    line = http.request_line(raw)
    target, absolute = http.origin_form(line.target)

    if absolute:
      return target, Service(*absolute)

    secure = current.secure if current else True
    host = http.parse(raw).header("Host")

    if not host:
      if current is None:
        raise ValueError("request has no Host header")
      return target, current

    return target, Service(*http.split_host(host, secure), secure)

  def _apply_request(self, rec: Record, raw: bytes, current: Optional[Service], secure: Optional[bool],
                     service: Optional[Service] = None) -> None:
    explicit = service is not None
    if explicit:
      target, _ = http.origin_form(http.request_line(raw).target)
    else:
      target, service = self._target_service(raw, current)

    if not explicit and secure is not None and secure != service.secure:
      default = 443 if service.secure else 80
      port = (443 if secure else 80) if service.port == default else service.port
      service = Service(service.host, port, secure)

    line = http.request_line(raw)
    self._set_string(rec, 1, line.method)
    rec.set_u64(2, self._url_key(intern_service(self._store, self._root, service), target))
    self._set_string(rec, 3, http.extension(target))
    self._store.write(rec.fields[5], bytes([int(http.has_parameters(raw))]))

  def _apply_response(self, rec: Record, raw: bytes) -> None:
    self._store.write(rec.fields[6], http.status_code(raw).to_bytes(2, "big"))
    self._store.write(rec.fields[7], http.mime_code(raw).to_bytes(2, "big"))
    rec.set_u32(8, len(raw))
    self._set_string(rec, 9, http.title(raw))
    self._set_string(rec, 10, http.cookies_summary(raw))

  def _set_protocol(self, rec: Record, field_id: int, value: int) -> None:
    self._store.write(rec.fields[field_id], bytes([value]))

  def edit_request(self, number: int, raw: bytes, keep_original: bool = False,
                   secure: Optional[bool] = None) -> None:
    """Replace the request of history item `number`.

    By default the original request is overwritten and any auto-modified or
    edited versions are dropped, so Burp shows the new request. With
    `keep_original` the new request is stored as the *edited* request, the
    way Burp records a request changed in the interceptor.
    """
    rec = self._find(number)
    http.validate_request(raw)
    raw = http.normalize(raw, is_request=True)
    current = Service.from_record(rec.record(2).record(0)) if rec.ref(2) else None

    # Fail on a request without a known target before writing anything.
    self._target_service(raw, current)
    protocol = http.protocol_id(raw)

    if keep_original:
      rec.set_u64(17, self._store.new_array(raw))
      rec.set_u64(23, 0)
      self._set_protocol(rec, 26, protocol)
    else:
      rec.set_u64(15, self._store.new_array(raw))
      rec.set_u64(21, 0)
      self._set_protocol(rec, 24, protocol)

      for data, parts, protocol_field in ((16, 22, 25), (17, 23, 26)):
        rec.set_u64(data, 0)
        rec.set_u64(parts, 0)
        self._set_protocol(rec, protocol_field, PROTOCOL_UNKNOWN)

    self._apply_request(rec, raw, current, secure)

  def edit_response(self, number: int, raw: bytes, keep_original: bool = False) -> None:
    """Replace the response of history item `number` (see `edit_request`)."""
    rec = self._find(number)
    raw = http.normalize(raw, is_request=False)

    if keep_original:
      rec.set_u64(20, self._store.new_array(raw))
    else:
      rec.set_u64(18, self._store.new_array(raw))
      rec.set_u64(19, 0)
      rec.set_u64(20, 0)

    self._apply_response(rec, raw)

  def set_comment(self, number: int, comment: Optional[str]) -> None:
    rec = self._find(number)
    text = self._store.record(rec.ref(27))

    if text is None:
      raise ValueError(f"history item #{number} has no comment slot")

    text.set_u64(2, self._text_nodes(comment))

  def _text_nodes(self, text: Optional[str]) -> int:
    """Linked char-array nodes of at most 100 chars: 1 chars, 2 length, 3 next."""
    node = 0

    for chunk in reversed([text[i:i + 100] for i in range(0, len(text or ""), 100)]):
      ptr = self._store.new_record([Field(1, 8), Field(2, 4, len(chunk)), Field(3, 8, node)])
      chars = chunk.encode("utf-16-be")
      self._store.write_u64(ptr + 13, self._store.new_array(chars, len(chars) // 2))
      node = ptr

    return node

  def append(self, request: bytes, response: Optional[bytes] = None, secure: bool = True,
             timestamp: Optional[datetime] = None, listener_port: int = DEFAULT_LISTENER_PORT,
             service: Optional[Service] = None, ip: Optional[str] = None,
             comment: Optional[str] = None) -> int:
    """Add a new item to the end of the history and return its number.

    The target service comes from the Host header (or an absolute request
    target) unless `service` is given.
    """
    http.validate_request(request)
    request = http.normalize(request, is_request=True)

    if service is None:
      # Fail on a request without a known target before writing anything.
      self._target_service(request, None)

    if response is not None:
      response = http.normalize(response, is_request=False)

    container = self._container
    # Burp keeps the last item number in field 4 (0 means "look at the list").
    last = container.u32(4) or max((rec.u32(0) for rec in self._records()), default=0)
    number = last + 1
    millis = int((timestamp.timestamp() if timestamp else time.time()) * 1000)

    # 28/29 are timings Burp leaves at -1 when unknown.
    values = {127: LIVE_MARKER, 0: number, 11: millis, 14: listener_port, 28: -1, 29: -1, 30: millis,
              24: http.protocol_id(request), 25: PROTOCOL_UNKNOWN, 26: PROTOCOL_UNKNOWN}

    ptr = self._store.new_record([Field(fid, size, values.get(fid, 0)) for fid, size in _ITEM_LAYOUT],
                                 type_id=ITEM_TYPE)
    rec = self._store.record(ptr)
    rec.set_u64(15, self._store.new_array(request))
    self._apply_request(rec, request, None, secure, service)

    if ip:
      self._set_string(rec, 4, ip)

    if response is not None:
      rec.set_u64(18, self._store.new_array(response))
      self._apply_response(rec, response)

    # Every item has a comment bound to the global text pool, even if empty.
    pool = self._store.record(self._store.store_root).ref(0)
    rec.set_u64(27, self._store.new_record([Field(1, 8, pool), Field(2, 8, self._text_nodes(comment))]))

    self._store.list_append(container.ref(ALL_ITEMS), ptr)
    # Without this Burp hides the new item until the display filter re-runs.
    self._store.list_append(container.ref(FILTERED_ITEMS), ptr)
    container.set_u32(4, number)

    return number

