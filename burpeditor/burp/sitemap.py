"""Target site map.

Application root field 3 holds four indexes over the same tree of nodes:
  0 map service -> host node, 1 map URL -> folder node,
  2 map URL -> request node, 3 set of all nodes.

Every node has 0 URL key, 1 display name, 2 parent, 3 children and its
record type tells what it is: 1 host, 2 folder, 3 request, 4 request with a
query string. Request nodes point (field 33) to the last message seen:
0 request, 1 response, 4 method, 5 status.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional

from burpeditor.burp.services import Service
from burpeditor.burp.store import Record, Store

ROOT_SITEMAP = 3
HOST, FOLDER, REQUEST, QUERY = 1, 2, 3, 4


@dataclass
class SiteMapNode:
  name: str
  kind: int
  url: str = ""
  method: Optional[str] = None
  status: Optional[int] = None
  requested: bool = False
  children: list["SiteMapNode"] = field(default_factory=list)

  def walk(self, depth: int = 0) -> Iterator[tuple[int, "SiteMapNode"]]:
    yield depth, self
    for child in self.children:
      yield from child.walk(depth + 1)


class SiteMap:
  def __init__(self, store: Store, root: Record) -> None:
    self._store = store
    self._root = root

  def hosts(self) -> list[SiteMapNode]:
    state = self._store.record(self._root.ref(ROOT_SITEMAP))
    nodes = []

    for key, value in self._store.map_entries(state.ref(0)):
      service = Service.from_record(self._store.record(key))
      nodes.append(self._node(self._store.record(value), service, set()))
      
    return sorted(nodes, key=lambda n: n.name)

  def _node(self, rec: Record, service: Optional[Service], seen: set[int]) -> SiteMapNode:
    seen.add(rec.offset)
    key = rec.record(0)
    target = (key.array(1) or b"").decode("latin-1") if key else ""
    node = SiteMapNode(
      name=rec.string(1) or target or (service.origin if service else ""),
      kind=rec.type_id,
      url=(service.origin if service else "") + target,
    )
    if rec.type_id in (REQUEST, QUERY) and 33 in rec:
      message = rec.record(33)
      if message is not None:
        node.method = self._store.string_n(message.ref(4))
        node.status = message.u16(5) or None
        node.requested = bool(message.ref(0))
    for child in self._store.iter_records(rec.list(3)):
      if child.offset not in seen:
        node.children.append(self._node(child, service, seen))
    node.children.sort(key=lambda n: n.name)
    return node
