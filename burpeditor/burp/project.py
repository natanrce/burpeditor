import gzip
import os
import secrets
import string
from importlib import resources
from typing import Optional

from burpeditor.burp.history import HTTPHistory
from burpeditor.burp.scanner import Scanner
from burpeditor.burp.sitemap import SiteMap
from burpeditor.burp.store import (ALLOC_END_OFFSET, CLEAN_TAIL, FORMAT_VERSION, MAGIC_BYTES,
                                   Record, Store)

# The skeleton holds the objects Burp writes when it creates a project
# (store root, text pool, application root with its tools and default
# project options), with every data collection and identifier removed.
# The fields below are left null in it and filled in by `create`.
_SKELETON_END = 68500
_SKELETON_STRINGS = {
  299: "install_id",
  347: "project_name",
  411: "project_uid",
}
_SKELETON_COLLECTIONS = {
  1074: lambda s: s.new_paged_list(200),  # proxy HTTP history
  1082: lambda s: s.new_paged_list(200),
  1090: lambda s: s.new_paged_list(200),  # proxy WebSockets history
  1098: lambda s: s.new_paged_list(200),
  2121: lambda s: s.new_map(32),          # site map indexes
  2129: lambda s: s.new_map(32),
  2137: lambda s: s.new_map(32),
  2145: lambda s: s.new_set(32),
  2153: lambda s: s.new_list(capacity=10),
  339: lambda s: s.new_list(capacity=10),  # HTTP services
  451: lambda s: s.new_list(capacity=10),  # scanner tasks
  467: lambda s: s.new_paged_list(200),   # scanner issues
  53791: lambda s: s.new_array(secrets.token_bytes(32)),  # project keys
  36879: lambda s: s.new_array(secrets.token_bytes(32)),
  371: lambda s: s.new_paged_list(50),
  95: lambda s: s.new_paged_list(10),     # text pool free list
}
_ID_ALPHABET = string.ascii_lowercase + string.digits
_MIN_FILE_SIZE = 32768

def _random_id(length: int) -> str:
  return "".join(secrets.choice(_ID_ALPHABET) for _ in range(length))

class BurpProject:
  """A .burp project.

  Used as a context manager, a writable project is finalized when the block
  ends normally. With `discard_on_error` its file is deleted if the block
  raises instead, for files that only exist for that block (new projects,
  copies being edited).
  """
  def __init__(self, store: Store, discard_on_error: bool = False) -> None:
    self.store = store
    self.discard_on_error = discard_on_error
    self.root: Record = store.record(store.app_root)

    if self.root is None:
      raise ValueError("Burpsuite project has no application root")

  @classmethod
  def open(cls, path: str, writable: bool = False, discard_on_error: bool = False) -> "BurpProject":
    return cls(Store.open(path, writable), discard_on_error=discard_on_error)

  @classmethod
  def create(cls, path: str, name: Optional[str] = None, force: bool = False) -> "BurpProject":
    """Create a new, empty project file without Burp.

    The project is discarded on error (see the class docstring).
    """
    if os.path.exists(path) and not force:
      raise FileExistsError(f"{path} already exists")

    skeleton = gzip.decompress(resources.files("burpeditor.burp").joinpath("data/skeleton.bin.gz").read_bytes())
    assert len(skeleton) == _SKELETON_END and int.from_bytes(skeleton[:4], "big") == MAGIC_BYTES
    
    with open(path, "wb") as f:
      f.write(skeleton)
    
    if name is None:
      name = os.path.splitext(os.path.basename(path))[0]

    store = Store.open(path, writable=True)

    try:
      cls._fill_skeleton(store, name)
    except BaseException:
      store.close()
      os.remove(path)
      raise

    project = cls(store, discard_on_error=True)
    project.finalize()
    return project

  @staticmethod
  def _fill_skeleton(store: Store, name: str) -> None:
    """Set the header and the identifiers and empty collections left out of the skeleton."""
    store.write(12, FORMAT_VERSION.to_bytes(2, "big") * 2)
    store.write_u32(16, secrets.randbits(32))
    store.write_u64(ALLOC_END_OFFSET, _SKELETON_END)

    strings = {"install_id": _random_id(20), "project_name": name, "project_uid": _random_id(20)}

    for offset, role in _SKELETON_STRINGS.items():
      store.write_u64(offset, store.new_string(strings[role]))

    for offset, build in _SKELETON_COLLECTIONS.items():
      store.write_u64(offset, build(store))

  def finalize(self) -> None:
    """Size the file the way Burp expects: zeros after the allocation end."""
    end = self.store.alloc_end
    size = _MIN_FILE_SIZE

    while size < end + CLEAN_TAIL:
      size *= 2
    
    self.store.resize(max(size, self.store.size))

  def close(self) -> None:
    self.store.close()

  def __enter__(self) -> "BurpProject":
    return self

  def __exit__(self, exc_type, *_) -> None:
    if exc_type is None and self.store.writable:
      self.finalize()

    self.close()

    if exc_type is not None and self.discard_on_error:
      os.remove(self.path)

  @property
  def path(self) -> str:
    return self.store.path

  @property
  def name(self) -> Optional[str]:
    return self.root.string(6)

  @property
  def http_history(self) -> HTTPHistory:
    return HTTPHistory(self.store, self.root)

  @property
  def scanner(self) -> Scanner:
    return Scanner(self.store, self.root)

  @property
  def issues(self):
    return self.scanner.issues()

  @property
  def tasks(self):
    return self.scanner.tasks()

  @property
  def sitemap(self) -> SiteMap:
    return SiteMap(self.store, self.root)

