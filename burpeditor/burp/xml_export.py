"""Burp's XML export of HTTP items (Proxy history / site map "Save items").

  <items burpVersion="..." exportTime="...">
    <item>
      <time>Sun Oct 04 23:37:53 GMT-03:00 2026</time>
      <url>, <host ip="...">, <port>, <protocol>, <method>, <path>, <extension>,
      <request base64="true">...</request>, <status>, <responselength>,
      <mimetype>, <response base64="true">...</response>, <comment>
    </item>
  </items>
"""
from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import BinaryIO, Iterator, Optional, Union

from burpeditor.burp.services import Service

# Java's Date.toString(): "EEE MMM dd HH:mm:ss zzz yyyy", the zone being
# either an offset ("GMT-03:00") or an abbreviation ("BRT").
_TIME_RE = re.compile(
  r"^\w{3} (?P<month>\w{3}) (?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
  r"(?P<zone>\S+) (?P<year>\d{4})$"
)
_OFFSET_RE = re.compile(r"^(?:GMT|UTC)?(?P<sign>[+-])(?P<hours>\d{1,2}):?(?P<minutes>\d{2})?$")


@dataclass
class ExportedItem:
  time: Optional[datetime]
  service: Service
  ip: Optional[str]
  request: bytes
  response: Optional[bytes]
  comment: Optional[str]


def parse_time(value: Optional[str]) -> Optional[datetime]:
  match = _TIME_RE.match((value or "").strip())
  if not match:
    return None
  try:
    moment = datetime.strptime(f"{match['day']} {match['month']} {match['year']} {match['time']}",
                               "%d %b %Y %H:%M:%S")
  except ValueError:
    return None
  zone = match["zone"]
  offset = _OFFSET_RE.match(zone)
  if offset:
    delta = timedelta(hours=int(offset["hours"]), minutes=int(offset["minutes"] or 0))
    return moment.replace(tzinfo=timezone(delta if offset["sign"] == "+" else -delta))
  if zone in ("GMT", "UTC"):
    return moment.replace(tzinfo=timezone.utc)
  # Unknown abbreviation: assume the local time zone.
  return moment.astimezone()


def _message(element: Optional[ET.Element]) -> Optional[bytes]:
  if element is None or not element.text:
    return None

  if element.get("base64") == "true":
    return base64.b64decode(element.text)

  return element.text.encode("latin-1", errors="replace")


def _text(element: Optional[ET.Element]) -> Optional[str]:
  text = (element.text or "").strip() if element is not None else ""
  return text or None


def read_items(source: Union[str, BinaryIO]) -> Iterator[ExportedItem]:
  """Yield the items of an export, streaming so large files fit in memory."""
  root = None
  for event, element in ET.iterparse(source, events=("start", "end")):
    if event == "start":
      if root is None:
        root = element
        if root.tag != "items":
          raise ValueError("not a Burp XML export (missing <items>)")
      continue
    if element.tag != "item":
      continue
    request = _message(element.find("request"))
    if request is None:
      raise ValueError("export item without a request")
    host = element.find("host")
    protocol = (_text(element.find("protocol")) or "https").lower()
    port = _text(element.find("port"))
    yield ExportedItem(
      time=parse_time(_text(element.find("time"))),
      service=Service(_text(host) or "", int(port) if port else (443 if protocol == "https" else 80),
                      protocol == "https"),
      ip=(host.get("ip") or None) if host is not None else None,
      request=request,
      response=_message(element.find("response")),
      comment=_text(element.find("comment")),
    )
    root.clear()
