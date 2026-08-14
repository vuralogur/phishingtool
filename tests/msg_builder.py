"""Build a real (small) Outlook .msg in memory, so the .msg tests use no fixture.

A checked-in binary would be untestable to review and impossible to tweak; this
writes the MS-CFB container the same way Outlook does - 512-byte sectors, small
streams packed into the mini stream, large ones in their own sector chain - so
detector/msg.py is exercised on both storage paths.
"""
from __future__ import annotations
from datetime import datetime, timezone
import struct

SECTOR = 512
MINI = 64
CUTOFF = 4096
_ENDOFCHAIN = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_FREESECT = 0xFFFFFFFF
_NOSTREAM = 0xFFFFFFFF
_SIG = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class Node:
    """A CFB storage (kind 1) or stream (kind 2)."""

    def __init__(self, name: str, kind: int, data: bytes = b""):
        self.name = name
        self.kind = kind
        self.data = data
        self.children = []
        self.start = 0
        self.size = len(data)

    def add(self, child: "Node") -> "Node":
        self.children.append(child)
        return child


def uni(pid: str, text: str) -> Node:
    """Unicode (PT_UNICODE, 001F) property stream."""
    return Node("__substg1.0_" + pid + "001F", 2, text.encode("utf-16-le"))


def ansi(pid: str, text: str, codec: str = "cp1254") -> Node:
    """8-bit (PT_STRING8, 001E) property stream - decoded via the codepage prop."""
    return Node("__substg1.0_" + pid + "001E", 2, text.encode(codec))


def binary(pid: str, data: bytes) -> Node:
    """Binary (PT_BINARY, 0102) property stream."""
    return Node("__substg1.0_" + pid + "0102", 2, data)


def properties(fixed: dict, header: int = 32) -> Node:
    """__properties_version1.0: {tag hex: 8 value bytes} -> 16-byte records."""
    raw = bytearray(b"\x00" * header)
    for tag, value in fixed.items():
        raw += struct.pack("<II", int(tag, 16), 0) + value.ljust(8, b"\x00")[:8]
    return Node("__properties_version1.0", 2, bytes(raw))


def filetime(when: datetime) -> bytes:
    delta = when.astimezone(timezone.utc) - datetime(1601, 1, 1, tzinfo=timezone.utc)
    return struct.pack("<Q", int(delta.total_seconds() * 10_000_000))


def _dir_entry(name: str, kind: int, left: int, right: int, child: int,
               start: int, size: int) -> bytes:
    raw = bytearray(b"\x00" * 128)
    encoded = name.encode("utf-16-le")[:62] + b"\x00\x00"
    raw[:len(encoded)] = encoded
    struct.pack_into("<H", raw, 64, len(encoded))
    raw[66] = kind
    raw[67] = 1  # black
    struct.pack_into("<3I", raw, 68, left, right, child)
    struct.pack_into("<II", raw, 116, start, size)
    return bytes(raw)


def _sectors(n_bytes: int) -> int:
    return (n_bytes + SECTOR - 1) // SECTOR


def to_bytes(root: Node) -> bytes:
    """Serialize a node tree into a .msg / CFB byte string."""
    nodes = [root]

    def walk(node):
        for child in node.children:
            nodes.append(child)
        for child in node.children:
            walk(child)

    walk(root)
    index = {id(n): i for i, n in enumerate(nodes)}

    # Small streams go into the mini stream, everything else gets real sectors.
    ministream, minifat, big = bytearray(), [], []
    for node in nodes[1:]:
        if node.kind != 2 or not node.data:
            node.start = _ENDOFCHAIN if node.kind == 2 else _NOSTREAM
            continue
        if len(node.data) < CUTOFF:
            node.start = len(ministream) // MINI
            count = (len(node.data) + MINI - 1) // MINI
            minifat += list(range(node.start + 1, node.start + count)) + [_ENDOFCHAIN]
            ministream += node.data.ljust(count * MINI, b"\x00")
        else:
            big.append(node)

    minifat_raw = b"".join(struct.pack("<I", x) for x in minifat)
    dir_sectors = _sectors(len(nodes) * 128)
    minifat_sectors = _sectors(len(minifat_raw))
    mini_sectors = _sectors(len(ministream))

    # The FAT has to describe itself, so grow it until it covers every sector.
    n_fat = 1
    while True:
        base = n_fat
        dir_start, base = base, base + dir_sectors
        minifat_start, base = base, base + minifat_sectors
        mini_start, base = base, base + mini_sectors
        for node in big:
            node.start, base = base, base + _sectors(len(node.data))
        if base <= n_fat * (SECTOR // 4):
            break
        n_fat += 1

    total = base
    fat = [_FREESECT] * (n_fat * (SECTOR // 4))
    for s in range(n_fat):
        fat[s] = _FATSECT

    def chain(start: int, count: int):
        for s in range(start, start + count - 1):
            fat[s] = s + 1
        if count:
            fat[start + count - 1] = _ENDOFCHAIN

    chain(dir_start, dir_sectors)
    chain(minifat_start, minifat_sectors)
    chain(mini_start, mini_sectors)
    for node in big:
        chain(node.start, _sectors(len(node.data)))

    # Directory: children hang off the parent as a right-sibling chain.
    parent_of = {}
    for node in nodes:
        for child in node.children:
            parent_of[id(child)] = node
    directory = bytearray()
    for node in nodes:
        child = index[id(node.children[0])] if node.children else _NOSTREAM
        right = _NOSTREAM
        parent = parent_of.get(id(node))
        if parent is not None:
            pos = parent.children.index(node)
            if pos + 1 < len(parent.children):
                right = index[id(parent.children[pos + 1])]
        if node is root:
            directory += _dir_entry("Root Entry", 5, _NOSTREAM, _NOSTREAM, child,
                                    mini_start, len(ministream))
        else:
            size = len(node.data) if node.kind == 2 else 0
            start = node.start if node.kind == 2 else 0
            directory += _dir_entry(node.name, node.kind, _NOSTREAM, right, child,
                                    start, size)

    header = bytearray(b"\x00" * SECTOR)
    header[:8] = _SIG
    struct.pack_into("<HH", header, 24, 0x3E, 3)      # version 3
    struct.pack_into("<H", header, 28, 0xFFFE)        # little endian
    struct.pack_into("<HH", header, 30, 9, 6)         # 512 / 64 byte sectors
    struct.pack_into("<8I", header, 44,
                     n_fat, dir_start, 0, CUTOFF,
                     minifat_start, minifat_sectors, _ENDOFCHAIN, 0)
    for i in range(109):
        struct.pack_into("<I", header, 76 + i * 4, i if i < n_fat else _FREESECT)

    body = bytearray(b"\x00" * (total * SECTOR))

    def put(sector: int, data: bytes):
        body[sector * SECTOR:sector * SECTOR + len(data)] = data

    for i in range(n_fat):
        put(i, b"".join(struct.pack("<I", x) for x in fat[i * 128:(i + 1) * 128]))
    put(dir_start, bytes(directory))
    put(minifat_start, minifat_raw)
    put(mini_start, bytes(ministream))
    for node in big:
        put(node.start, node.data)
    return bytes(header) + bytes(body)


def message(transport: str = "", subject: str = "", body: str = "",
            html: str = "", sender=("", ""), repr_sender=None,
            recipients=(), attachments=(), when: datetime = None,
            codepage: int = 0, ansi_body: bool = False) -> bytes:
    """Assemble a .msg from the pieces a test cares about.

    ``sender``/``repr_sender`` are ``(display name, smtp address)``;
    ``recipients`` are ``(name, address, kind)`` with 1=To, 2=Cc;
    ``attachments`` are ``(filename, mime type, bytes)``.
    """
    root = Node("Root Entry", 5)
    if transport:
        root.add(uni("007D", transport))
    if subject:
        root.add(uni("0037", subject))
    if body:
        root.add(ansi("1000", body) if ansi_body else uni("1000", body))
    if html:
        root.add(binary("1013", html.encode("cp1254" if codepage else "utf-8")))
    name, addr = sender
    if name:
        root.add(uni("0C1A", name))
    if addr:
        root.add(uni("5D01", addr))
    if repr_sender:
        rname, raddr = repr_sender
        if rname:
            root.add(uni("0042", rname))
        if raddr:
            root.add(uni("5D02", raddr))

    for i, (rname, raddr, kind) in enumerate(recipients):
        storage = root.add(Node("__recip_version1.0_#%08X" % i, 1))
        storage.add(uni("3001", rname))
        storage.add(uni("39FE", raddr))
        storage.add(properties({"0C150003": struct.pack("<I", kind)}, header=8))

    for i, (fname, mime, data) in enumerate(attachments):
        storage = root.add(Node("__attach_version1.0_#%08X" % i, 1))
        storage.add(uni("3707", fname))
        storage.add(uni("370E", mime))
        storage.add(binary("3701", data))

    fixed = {}
    if when:
        fixed["00390040"] = filetime(when)
    if codepage:
        fixed["3FDE0003"] = struct.pack("<I", codepage)
    root.add(properties(fixed))
    return to_bytes(root)
