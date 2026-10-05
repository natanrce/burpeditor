"""Low-level access to the object store behind a .burp project file.

A project file is a memory-mapped heap managed by a bump allocator:

  header (72 bytes)
    0   u32  magic            0x66858280
    4   u32  store version    1
    8   u32  file signature   0x80527974
    12  u16  created by format version
    14  u16  format version
    16  u32  random project id
    40  u64  store root       (always 72)
    48  u64  segment size     (0x7fffffffffffffff: single segment)
    56  u64  allocation end   (next free offset)
    64  u64  application root

Every object is a record:

  u8  flags          bit 0 set -> object moved, u64 forward pointer at offset 1
  u8  type id        subtype of a polymorphic schema
  u8  schema version
  u8  field count
  field count * (u8 field id, u16 field offset from record start)
  field values       big-endian, pointers are absolute u64 offsets

Primitive arrays (byte/char/pointer arrays) have no record header:

  u32 total size (8 + data size, at least 9)
  u32 element count
  data
"""
from __future__ import annotations

import mmap
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Iterator, Optional

MAGIC_BYTES = 0x66858280
STORE_VERSION = 1
FILE_SIGNATURE = 0x80527974
FORMAT_VERSION = 222

HEADER_SIZE = 72
STORE_ROOT_OFFSET = 40
SEGMENT_SIZE_OFFSET = 48
ALLOC_END_OFFSET = 56
APP_ROOT_OFFSET = 64
SINGLE_SEGMENT = 0x7FFFFFFFFFFFFFFF

_GROWTH_STEP = 1024 * 1024
_MAX_FORWARDS = 32
_LOAD_FACTOR_BITS = 0x3F400000  # 0.75f
_HASH_CODE_VERSION = 2
# Burp treats the project as dirty unless this many bytes after the
# allocation end are zero (or the file ends there).
CLEAN_TAIL = 1024

class StoreError(ValueError):
  pass

@dataclass(frozen=True)
class Field:
  """A field value to be written in a new record."""
  id: int
  size: int
  value: int = 0

  def encode(self) -> bytes:
    return self.value.to_bytes(self.size, "big", signed=self.value < 0)

class Record:
  def __init__(self, store: "Store", offset: int) -> None:
    self.store = store
    self.offset = offset
    self.type_id = store.u8(offset + 1)
    self.version = store.u8(offset + 2)
    self.fields: dict[int, int] = {}

    count = store.u8(offset + 3)
    
    for i in range(count):
      desc = offset + 4 + i * 3
      self.fields[store.u8(desc)] = offset + store.u16(desc + 1)

  def __contains__(self, field_id: int) -> bool:
    return field_id in self.fields

  def __repr__(self) -> str:
    return f"Record(@{self.offset}, type={self.type_id}, version={self.version}, fields={sorted(self.fields)})"

  def _at(self, field_id: int) -> Optional[int]:
    return self.fields.get(field_id)

  def u8(self, field_id: int, default: int = 0) -> int:
    at = self._at(field_id)
    return default if at is None else self.store.u8(at)

  def bool(self, field_id: int, default: bool = False) -> bool:
    return bool(self.u8(field_id, int(default)))

  def u16(self, field_id: int, default: int = 0) -> int:
    at = self._at(field_id)
    return default if at is None else self.store.u16(at)

  def u32(self, field_id: int, default: int = 0) -> int:
    at = self._at(field_id)
    return default if at is None else self.store.u32(at)

  def i32(self, field_id: int, default: int = 0) -> int:
    at = self._at(field_id)
    return default if at is None else self.store.i32(at)

  def u64(self, field_id: int, default: int = 0) -> int:
    at = self._at(field_id)
    return default if at is None else self.store.u64(at)

  def i64(self, field_id: int, default: int = 0) -> int:
    at = self._at(field_id)
    return default if at is None else self.store.i64(at)

  ref = u64

  def record(self, field_id: int) -> Optional["Record"]:
    return self.store.record(self.ref(field_id))

  def string(self, field_id: int) -> Optional[str]:
    return self.store.string(self.ref(field_id))

  def array(self, field_id: int) -> Optional[bytes]:
    return self.store.array(self.ref(field_id))

  def list(self, field_id: int) -> list[int]:
    return self.store.list_items(self.ref(field_id))

  def set_u64(self, field_id: int, value: int) -> None:
    at = self._at(field_id)
    
    if at is None:
      raise StoreError(f"record @{self.offset} has no field {field_id}")

    self.store.write_u64(at, value)

  def set_u32(self, field_id: int, value: int) -> None:
    at = self._at(field_id)

    if at is None:
      raise StoreError(f"record @{self.offset} has no field {field_id}")

    self.store.write_u32(at, value)

class Store:
  """Memory-mapped view of a .burp file, optionally writable."""

  def __init__(self, file: BinaryIO, writable: bool = False) -> None:
    self._file = file
    self._writable = writable
    self._map: Optional[mmap.mmap] = None
    
    self._remap()

    if self.size < HEADER_SIZE or self.u32(0) != MAGIC_BYTES:
      raise StoreError("File is not a valid Burpsuite project")
    
    if self.u32(4) != STORE_VERSION or self.u32(8) != FILE_SIGNATURE:
      raise StoreError("Unsupported Burpsuite project store version")

    if not HEADER_SIZE <= self.alloc_end <= self.size:
      raise StoreError("Burpsuite project file is truncated or corrupted")

  @classmethod
  def open(cls, path: str, writable: bool = False) -> "Store":
    return cls(open(path, "r+b" if writable else "rb"), writable)

  def close(self) -> None:
    if self._map is not None:
      if self._writable:
        self._map.flush()
      self._map.close()
      self._map = None
    self._file.close()

  def __enter__(self) -> "Store":
    return self

  def __exit__(self, *_) -> None:
    self.close()

  def _remap(self) -> None:
    if self._map is not None:
      self._map.close()
    access = mmap.ACCESS_WRITE if self._writable else mmap.ACCESS_READ
    self._map = mmap.mmap(self._file.fileno(), 0, access=access)

  @property
  def path(self) -> str:
    return self._file.name

  @property
  def writable(self) -> bool:
    return self._writable

  @property
  def size(self) -> int:
    return len(self._map)

  @property
  def alloc_end(self) -> int:
    return self.u64(ALLOC_END_OFFSET)

  @property
  def format_version(self) -> int:
    return self.u16(14)

  @property
  def project_id(self) -> int:
    return self.u32(16)

  @property
  def store_root(self) -> int:
    return self.u64(STORE_ROOT_OFFSET)

  @property
  def app_root(self) -> int:
    return self.u64(APP_ROOT_OFFSET)

  def valid(self, ptr: int) -> bool:
    return HEADER_SIZE <= ptr < self.alloc_end

  def u8(self, offset: int) -> int:
    return self._map[offset]

  def u16(self, offset: int) -> int:
    return struct.unpack_from(">H", self._map, offset)[0]

  def u32(self, offset: int) -> int:
    return struct.unpack_from(">I", self._map, offset)[0]

  def i32(self, offset: int) -> int:
    return struct.unpack_from(">i", self._map, offset)[0]

  def u64(self, offset: int) -> int:
    return struct.unpack_from(">Q", self._map, offset)[0]

  def i64(self, offset: int) -> int:
    return struct.unpack_from(">q", self._map, offset)[0]

  def read(self, offset: int, length: int) -> bytes:
    return bytes(self._map[offset:offset + length])

  def resolve(self, ptr: int) -> int:
    """Follow forward pointers left behind when Burp relocates an object."""
    for _ in range(_MAX_FORWARDS):
      if not self._map[ptr] & 1:
        return ptr

      ptr = self.u64(ptr + 1)

      if not self.valid(ptr):
        raise StoreError(f"invalid forward pointer {ptr}")

    raise StoreError("forward pointer chain too long")

  def record(self, ptr: int) -> Optional[Record]:
    if not ptr:
      return None

    if not self.valid(ptr):
      raise StoreError(f"invalid object pointer {ptr}")

    return Record(self, self.resolve(ptr))

  def array_info(self, ptr: int) -> tuple[int, int]:
    """Return (data size, element count) of a primitive array."""
    total, count = self.u32(ptr), self.u32(ptr + 4)
    return (0 if count == 0 else total - 8), count

  def array(self, ptr: int) -> Optional[bytes]:
    if not ptr:
      return None

    if not self.valid(ptr):
      raise StoreError(f"invalid array pointer {ptr}")

    size, _ = self.array_info(ptr)
    return self.read(ptr + 8, size)

  def pointers(self, ptr: int) -> list[int]:
    if not ptr:
      return []

    _, count = self.array_info(ptr)
    return list(struct.unpack_from(f">{count}Q", self._map, ptr + 8))

  def string(self, ptr: int) -> Optional[str]:
    """Decode a string object: field 0 -> UTF-16BE char array."""
    rec = self.record(ptr)

    if rec is None:
      return None

    chars = self.array(rec.ref(0))
    return "" if chars is None else chars.decode("utf-16-be", errors="replace")

  def list_items(self, ptr: int) -> list[int]:
    """Items of a persistent list.

    Two layouts exist: a flat list (0: count, 1: pointer array) and a paged
    list (0: count, 1: page size, 2: flat list of pointer-array pages,
    3: index of the first item in the first page).
    """
    rec = self.record(ptr)
    if rec is None:
      return []
    count = rec.u32(0)
    if 2 in rec:
      start = rec.u32(3)
      items: list[int] = []
      for page in self.list_items(rec.ref(2)):
        items.extend(self.pointers(page))
      return items[start:start + count]
    return self.pointers(rec.ref(1))[:count]

  def string_n(self, ptr: int) -> Optional[str]:
    """Decode a chunked string: 0 length, 1 hash, 2 chunk size, 3 list of char arrays."""
    rec = self.record(ptr)
    if rec is None:
      return None
    chars = b"".join(self.array(chunk) or b"" for chunk in self.list_items(rec.ref(3)))
    return chars.decode("utf-16-be", errors="replace")[:rec.u32(0)]

  def text(self, ptr: int) -> Optional[str]:
    """Decode a pooled text (comments): 1 pool, 2 linked list of char-array nodes."""
    rec = self.record(ptr)
    if rec is None:
      return None
    parts = []
    node = self.record(rec.ref(2))
    while node is not None:
      parts.append((self.array(node.ref(1)) or b"").decode("utf-16-be", errors="replace")[:node.u32(2)])
      node = self.record(node.ref(3))
    return "".join(parts)

  def set_entries(self, ptr: int) -> list[tuple[int, int, int]]:
    """Entries (hash, key, value) of a persistent hash set (or a map's key set)."""
    rec = self.record(ptr)
    if rec is None:
      return []
    entries = []
    for bucket in self.iter_records(self.list_items(rec.ref(3))):
      data = self.array(bucket.ref(1)) or b""
      for i in range(bucket.u32(0)):
        entries.append(struct.unpack_from(">qQQ", data, i * 24))
    return entries

  def map_entries(self, ptr: int) -> list[tuple[int, int]]:
    """(key, value) pointers of a persistent hash map."""
    rec = self.record(ptr)
    if rec is None:
      return []
    return [(key, value) for _, key, value in self.set_entries(rec.ref(0))]

  def iter_records(self, ptrs: Iterable[int]) -> Iterator[Record]:
    for ptr in ptrs:
      rec = self.record(ptr)
      if rec is not None:
        yield rec

  def _require_writable(self) -> None:
    if not self._writable:
      raise StoreError("store was opened read-only")

  def _ensure_size(self, end: int) -> None:
    if end <= self.size:
      return
    new_size = (end + _GROWTH_STEP - 1) // _GROWTH_STEP * _GROWTH_STEP
    self._map.flush()
    self._file.truncate(new_size)
    self._remap()

  def resize(self, size: int) -> None:
    self._require_writable()
    if size < self.alloc_end:
      raise StoreError("cannot truncate allocated data")
    if size != self.size:
      self._map.flush()
      self._file.truncate(size)
      self._remap()

  def write(self, offset: int, data: bytes) -> None:
    self._require_writable()
    self._ensure_size(offset + len(data))
    self._map[offset:offset + len(data)] = data

  def write_u32(self, offset: int, value: int) -> None:
    self.write(offset, struct.pack(">I", value))

  def write_u64(self, offset: int, value: int) -> None:
    self.write(offset, struct.pack(">Q", value))

  def alloc(self, size: int) -> int:
    """Reserve `size` bytes the same way Burp does (even-aligned bump)."""
    self._require_writable()
    start = self.alloc_end
    if start % 2:
      start += 1
    self._ensure_size(start + size)
    self.write_u64(ALLOC_END_OFFSET, start + size)
    return start

  def new_record(self, fields: list[Field], type_id: int = 0, version: int = 0) -> int:
    header = 4 + 3 * len(fields)
    desc = bytearray()
    body = bytearray()
    for field in fields:
      desc += struct.pack(">BH", field.id, header + len(body))
      body += field.encode()
    ptr = self.alloc(header + len(body))
    self.write(ptr, bytes([0, type_id, version, len(fields)]) + bytes(desc) + bytes(body))
    return ptr

  def new_array(self, data: bytes, count: Optional[int] = None) -> int:
    count = len(data) if count is None else count
    total = 8 + max(len(data), 1)
    ptr = self.alloc(total)
    self.write(ptr, struct.pack(">II", total, count) + data.ljust(total - 8, b"\x00"))
    return ptr

  def new_pointer_array(self, ptrs: list[int], capacity: Optional[int] = None) -> int:
    capacity = max(capacity or 0, len(ptrs))
    data = struct.pack(f">{capacity}Q", *(ptrs + [0] * (capacity - len(ptrs))))
    return self.new_array(data, capacity)

  def new_string(self, value: str) -> int:
    ptr = self.new_record([Field(0, 8), Field(1, 4)])
    chars = value.encode("utf-16-be")
    self.write_u64(ptr + 10, self.new_array(chars, len(chars) // 2))
    return ptr

  def new_list(self, ptrs: Optional[list[int]] = None, capacity: int = 10) -> int:
    ptrs = ptrs or []
    ptr = self.new_record([Field(0, 4, len(ptrs)), Field(1, 8)])
    self.write_u64(ptr + 14, self.new_pointer_array(ptrs, capacity))
    return ptr

  def new_paged_list(self, page_size: int) -> int:
    """An empty paged list, laid out like Burp's own (record, page list, page array)."""
    ptr = self.new_record([Field(0, 4), Field(1, 4, page_size), Field(2, 8), Field(3, 4)])
    self.write_u64(ptr + 24, self.new_list())
    return ptr

  def new_set(self, capacity: int = 32) -> int:
    """An empty hash set with `capacity` buckets and a 0.75 load factor."""
    ptr = self.new_record([Field(0, 4, _LOAD_FACTOR_BITS), Field(2, 4), Field(1, 4, capacity * 3 // 4),
                           Field(3, 8), Field(4, 2, _HASH_CODE_VERSION)])
    page_size = capacity * 16
    buckets = self.new_record([Field(0, 4, capacity), Field(1, 4, page_size), Field(2, 8), Field(3, 4)])
    self.write_u64(ptr + 31, buckets)
    pages = self.new_record([Field(0, 4, 1), Field(1, 8)])
    self.write_u64(buckets + 24, pages)
    page_array = self.new_pointer_array([], 10)
    self.write_u64(pages + 14, page_array)
    self.write_u64(page_array + 8, self.new_pointer_array([], page_size))
    return ptr

  def new_map(self, capacity: int = 32) -> int:
    ptr = self.new_record([Field(0, 8)])
    self.write_u64(ptr + 7, self.new_set(capacity))
    return ptr

  def list_append(self, ptr: int, item: int) -> None:
    """Append `item` to a flat or paged list, growing its arrays like Burp does."""
    rec = self.record(ptr)
    if 2 not in rec:
      self._flat_append(rec, item)
      return
    count, page_size, start = rec.u32(0), rec.u32(1), rec.u32(3)
    pages = self.record(rec.ref(2))
    slot = start + count
    page_index, offset = divmod(slot, page_size)
    if page_index >= pages.u32(0):
      self._flat_append(pages, self.new_pointer_array([], page_size))
    page = self.pointers(pages.ref(1))[page_index]
    self.write_u64(page + 8 + 8 * offset, item)
    rec.set_u32(0, count + 1)

  def _flat_append(self, rec: Record, item: int) -> None:
    count, array = rec.u32(0), rec.ref(1)
    _, capacity = self.array_info(array)

    if count >= capacity:
      array = self.new_pointer_array(self.pointers(array)[:count], max(10, capacity * 2))
      rec.set_u64(1, array)

    self.write_u64(array + 8 + 8 * count, item)
    rec.set_u32(0, count + 1)


def is_project_file(path: str) -> bool:
  """Cheap check of the header of a .burp file, without mapping it."""
  try:
    with open(path, "rb") as f:
      header = f.read(12)
  except OSError:
    return False

  if len(header) < 12:
    return False

  magic, version, signature = struct.unpack(">III", header)
  return magic == MAGIC_BYTES and version == STORE_VERSION and signature == FILE_SIGNATURE
