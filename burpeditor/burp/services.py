"""HTTP services (host, port, protocol) interned in the project root."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from burpeditor.burp.store import Field, Record, Store

# Application root field holding the list of every service in the project.
ROOT_SERVICES = 5


@dataclass(frozen=True)
class Service:
  host: str
  port: int
  secure: bool

  @property
  def scheme(self) -> str:
    return "https" if self.secure else "http"

  @property
  def origin(self) -> str:
    default = 443 if self.secure else 80
    port = "" if self.port == default else f":{self.port}"

    return f"{self.scheme}://{self.host}{port}"

  @classmethod
  def from_record(cls, rec: Optional[Record]) -> Optional["Service"]:
    if rec is None:
      return None

    return cls(rec.string(0) or "", rec.u32(1), rec.bool(2))


def find_service(store: Store, root: Record, service: Service) -> Optional[int]:
  for ptr in store.list_items(root.ref(ROOT_SERVICES)):
    if Service.from_record(store.record(ptr)) == service:
      return ptr

  return None


def intern_service(store: Store, root: Record, service: Service) -> int:
  """Return the record of `service`, adding it to the project if needed."""
  ptr = find_service(store, root, service)

  if ptr is not None:
    return ptr
  # 0 host, 1 port, 2 https, 3 flags, 4 DNS resolve time, 5 IP bytes, 6 cached hash (0 = lazy)
  ptr = store.new_record([Field(0, 8), Field(1, 4, service.port), Field(2, 1, int(service.secure)),
                          Field(3, 1), Field(4, 8), Field(5, 8), Field(6, 4)])

  store.write_u64(ptr + 25, store.new_string(service.host))
  store.list_append(root.ref(ROOT_SERVICES), ptr)

  return ptr
