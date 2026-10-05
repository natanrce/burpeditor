"""Minimal raw HTTP message parsing used to derive the fields Burp caches."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# Response MIME type codes stored by Burp in history items.
MIME_CODES = {
  "html": 256, 
  "text": 257, 
  "css": 258, 
  "script": 259, 
  "json": 260,
  "image": 512, 
  "jpeg": 513, 
  "gif": 514, 
  "png": 515, 
  "svg": 518,
  "binary": 1025, 
  "font": 1537,
}
MIME_NAMES = {code: name for name, code in MIME_CODES.items()}

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class HTTPMessage:
  start_line: str = ""
  headers: list[tuple[str, str]] = field(default_factory=list)
  body: bytes = b""

  def header(self, name: str) -> Optional[str]:
    name = name.lower()

    for key, value in self.headers:
      if key.lower() == name:
        return value

    return None

  def header_values(self, name: str) -> list[str]:
    name = name.lower()
    return [value for key, value in self.headers if key.lower() == name]

def parse(raw: bytes) -> HTTPMessage:
  end = raw.find(b"\r\n\r\n")
  sep = 4
  if end == -1:
    end, sep = raw.find(b"\n\n"), 2
  if end == -1:
    end, sep = len(raw), 0
  lines = raw[:end].decode("latin-1").split("\n")
  msg = HTTPMessage(start_line=lines[0].rstrip("\r"), body=raw[end + sep:])
  for line in lines[1:]:
    line = line.rstrip("\r")
    name, colon, value = line.partition(":")
    if colon and name:
      msg.headers.append((name.strip(), value.strip()))
  return msg

@dataclass
class RequestLine:
  method: str
  target: str
  version: str

def request_line(raw: bytes) -> RequestLine:
  parts = parse(raw).start_line.split(" ")

  if len(parts) < 2 or not parts[0]:
    raise ValueError("invalid HTTP request line")

  return RequestLine(parts[0], parts[1], parts[2] if len(parts) > 2 else "HTTP/1.1")


def validate_request(raw: bytes) -> None:
  """Raise ValueError unless `raw` starts with a valid request line."""
  request_line(raw)


def split_host(value: str, secure: bool) -> tuple[str, int]:
  default = 443 if secure else 80
  if value.startswith("["):
    host, _, rest = value[1:].partition("]")
    return host, int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else default
  host, colon, port = value.rpartition(":")
  if colon and port.isdigit():
    return host, int(port)
  return value, default


def origin_form(target: str) -> tuple[str, Optional[tuple[str, int, bool]]]:
  """Split an absolute-form request target into (path, (host, port, secure))."""
  match = re.match(r"^(https?)://([^/?#]+)(.*)$", target, re.IGNORECASE)
  if not match:
    return target, None
  secure = match.group(1).lower() == "https"
  host, port = split_host(match.group(2), secure)
  return match.group(3) or "/", (host, port, secure)


def extension(target: str) -> Optional[str]:
  path = target.split("?", 1)[0].split("#", 1)[0]
  last = path.rsplit("/", 1)[-1]
  if "." not in last:
    return None
  ext = last.rsplit(".", 1)[1]
  return ext or None


def has_parameters(raw: bytes) -> bool:
  line = request_line(raw)
  if "?" in line.target and line.target.split("?", 1)[1]:
    return True
  msg = parse(raw)
  content_type = (msg.header("Content-Type") or "").lower()
  return bool(msg.body) and ("form" in content_type or "json" in content_type or "xml" in content_type)


def status_code(raw: bytes) -> int:
  parts = parse(raw).start_line.split(" ")
  return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0


def mime_code(raw: bytes) -> int:
  content_type = (parse(raw).header("Content-Type") or "").split(";", 1)[0].strip().lower()
  if not content_type:
    return 0
  kind, _, sub = content_type.partition("/")
  if "html" in sub:
    return MIME_CODES["html"]
  if "json" in sub:
    return MIME_CODES["json"]
  if "javascript" in sub or "ecmascript" in sub:
    return MIME_CODES["script"]
  if sub == "css":
    return MIME_CODES["css"]
  if kind == "image":
    return MIME_CODES.get({"jpg": "jpeg", "svg+xml": "svg"}.get(sub, sub), MIME_CODES["image"])
  if kind == "font" or "woff" in sub:
    return MIME_CODES["font"]
  if kind == "text":
    return MIME_CODES["text"]
  if sub == "octet-stream":
    return MIME_CODES["binary"]
  return 0


def title(raw: bytes) -> Optional[str]:
  match = _TITLE_RE.search(parse(raw).body[:65536])
  if not match:
    return None
  return " ".join(match.group(1).decode("utf-8", errors="replace").split()) or None


def cookies_summary(raw: bytes) -> Optional[str]:
  cookies = [value.split(";", 1)[0].strip() for value in parse(raw).header_values("Set-Cookie")]
  return "; ".join(c for c in cookies if c) or None


def normalize(raw: bytes, is_request: bool) -> bytes:
  """Use CRLF line endings in the start line and headers, as Burp does.

  Messages written in a text editor usually end lines with LF only, which
  Burp shows as raw text. In a request without Content-Length or
  Transfer-Encoding, a body made only of line breaks is an editor artifact
  and is dropped; any other body gets a Content-Length header.
  """
  end, sep = raw.find(b"\r\n\r\n"), 4
  lf_end = raw.find(b"\n\n")
  if lf_end != -1 and (end == -1 or lf_end < end):
    end, sep = lf_end, 2
  if end == -1:
    end, sep = len(raw.rstrip(b"\r\n")), 0
  head = b"\r\n".join(line.rstrip(b"\r") for line in raw[:end].split(b"\n"))
  body = raw[end + sep:]
  msg = parse(head + b"\r\n\r\n")
  if is_request and not msg.header("Content-Length") and not msg.header("Transfer-Encoding"):
    if not body.strip(b"\r\n"):
      body = b""
    else:
      head += f"\r\nContent-Length: {len(body)}".encode()
  return head + b"\r\n\r\n" + body


def protocol_id(raw: bytes) -> int:
  """Burp's persisted HTTP version id: 1 for HTTP/1.x, 2 for HTTP/2."""
  version = request_line(raw).version.upper()
  return 2 if version.startswith("HTTP/2") else 1
