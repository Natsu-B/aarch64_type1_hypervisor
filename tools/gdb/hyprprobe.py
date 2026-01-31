# hyprprobe.py
# HyprProbe GDB Python helper
#
# Print origin backtrace without modifying registers.
# Colorize output with ANSI, always reset at end of printing.

import errno
import gdb
import os
import re
import struct
import sys
from typing import Dict, List, Optional, Tuple

sys.modules.setdefault("hyprprobe", sys.modules[__name__])

# ----------------------------
# Config
# ----------------------------

HPBT_USE_ANSI = True
HPBT_DISABLE_ANSI_ON_DUMB_TERM = True
HPBT_DISABLE_ANSI_WHEN_GDB_STYLE_OFF = False
HPBT_ORIGIN_INDEX = 0
HPBT_FP_MAX_DEPTH = 64
HPBT_FP_ALIGN = 16
HPBT_FP_MONOTONIC_ASCENDING = True
HPBT_FP_STOP_ON_UNKNOWN_PC = True
HPBT_ADJUST_LR_FOR_RESOLVE = True
HPBT_AUTO_ON_STOP_IF_PRESENT = False

HPSEMI_AUTO_ON_STOP = True
HPSEMI_READ_CHUNK = 512
HPSEMI_MAX_WRITE0 = 65536

# ----------------------------
# Internal state
# ----------------------------

_hpbt_busy = False
_hpbt_emitted_ansi = False
_semihost_busy = False
_semihost_files: Dict[int, object] = {}

_kv_re = re.compile(r"([A-Za-z0-9_]+)=([^;\s]+)")
_data_re = re.compile(r"\bdata=([0-9A-Fa-f]+)\b")

# ----------------------------
# ANSI helpers
# ----------------------------

_ANSI = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "gray": "\x1b[90m",
}

def _gdb_style_enabled() -> Optional[bool]:
    try:
        out = gdb.execute("show style enabled", to_string=True).strip().lower()
    except Exception:
        return None
    if "enabled" in out and "disabled" not in out:
        return True
    if "disabled" in out:
        return False
    return None

def _ansi_enabled() -> bool:
    if not HPBT_USE_ANSI:
        return False
    if HPBT_DISABLE_ANSI_ON_DUMB_TERM and os.environ.get("TERM", "") == "dumb":
        return False
    if HPBT_DISABLE_ANSI_WHEN_GDB_STYLE_OFF:
        se = _gdb_style_enabled()
        if se is False:
            return False
    return True

def _c(s: str, *styles: str) -> str:
    global _hpbt_emitted_ansi
    if not _ansi_enabled() or not styles:
        return s
    _hpbt_emitted_ansi = True
    prefix = "".join(_ANSI.get(st, "") for st in styles)
    return f"{prefix}{s}{_ANSI['reset']}"

def _force_ansi_reset() -> None:
    global _hpbt_emitted_ansi
    if _hpbt_emitted_ansi:
        gdb.write(_ANSI["reset"])
        _hpbt_emitted_ansi = False

# ----------------------------
# HyprProbe monitor
# ----------------------------

def _monitor(cmd: str) -> str:
    return gdb.execute(f"monitor {cmd}", to_string=True)

def _parse_kv(s: str) -> Dict[str, str]:
    d = {}
    for k, v in _kv_re.findall(s):
        d[k] = v
    return d

# ----------------------------
# Semihosting
# ----------------------------

_SEMIHOST_OPS = {
    0x01: "open",
    0x02: "close",
    0x04: "write0",
    0x05: "write",
}

_SEMIHOST_MODE_MAP = {
    0: "r",
    1: "rb",
    2: "r+",
    3: "r+b",
    4: "w",
    5: "wb",
    6: "w+",
    7: "w+b",
    8: "a",
    9: "ab",
    10: "a+",
    11: "a+b",
}

class SemihostReadError(Exception):
    def __init__(self, remaining: Optional[int] = None) -> None:
        super().__init__("semihost read empty")
        self.remaining = remaining

def _semihost_query() -> Optional[Dict[str, int]]:
    out = _monitor("hp semihost?").strip()
    if not out or out.startswith("no"):
        return None
    if not out.startswith("yes"):
        raise RuntimeError(f"semihost?: bad reply '{out}'")
    kv = _parse_kv(out)
    if "op" not in kv:
        raise RuntimeError("semihost?: missing op")
    return {
        "op": int(kv.get("op", "0"), 0),
        "args": int(kv.get("args", "0"), 0),
        "insn": int(kv.get("insn", "0"), 0),
    }

def _semihost_info() -> Dict[str, str]:
    out = _monitor("hp semihost info").strip()
    if out.startswith("error"):
        raise RuntimeError(out)
    return _parse_kv(out)

def _semihost_read_chunk(size: int) -> Tuple[bytes, bool]:
    out = _monitor(f"hp semihost read {size}").strip()
    if out.startswith("error"):
        raise RuntimeError(out)
    parts = out.split()
    if not parts or not parts[0].startswith("hex:"):
        raise RuntimeError(f"semihost read: bad reply '{out}'")
    hex_data = parts[0][4:]
    truncated = any(part.startswith("truncated=") and part.endswith("1") for part in parts[1:])
    if not hex_data:
        return (b"", truncated)
    try:
        return (bytes.fromhex(hex_data), truncated)
    except Exception as exc:
        raise RuntimeError(f"semihost read: hex decode failed: {exc}")

def _semihost_reply(result: int, err: int) -> None:
    out = _monitor(f"hp semihost reply {result} {err}").strip()
    if not out.startswith("ok"):
        raise RuntimeError(f"semihost reply failed: '{out}'")

def _semihost_alloc_handle() -> int:
    out = _monitor("hp semihost alloc_handle").strip()
    kv = _parse_kv(out)
    if "handle" not in kv:
        raise RuntimeError(f"semihost alloc_handle failed: '{out}'")
    return int(kv["handle"], 0)

def _semihost_read_write0() -> str:
    buf = bytearray()
    while True:
        chunk, truncated = _semihost_read_chunk(HPSEMI_READ_CHUNK)
        if not chunk and truncated:
            raise SemihostReadError()
        buf.extend(chunk)
        if len(buf) > HPSEMI_MAX_WRITE0:
            raise RuntimeError("semihost write0: too long")
        if not truncated:
            break
    return buf.decode(errors="replace")

def _semihost_read_exact(total_len: int) -> bytes:
    buf = bytearray()
    remaining = total_len
    while remaining > 0:
        read_len = min(HPSEMI_READ_CHUNK, remaining)
        chunk, _ = _semihost_read_chunk(read_len)
        if not chunk:
            raise SemihostReadError(remaining)
        buf.extend(chunk)
        remaining -= len(chunk)
    return bytes(buf)

def _semihost_open(info: Dict[str, str]) -> Tuple[int, int]:
    if "path" not in info or "len" not in info or "mode" not in info:
        return (-1, errno.EINVAL)
    try:
        path_len = int(info["len"], 0)
        mode = int(info["mode"], 0)
    except Exception:
        return (-1, errno.EINVAL)
    mode_str = _SEMIHOST_MODE_MAP.get(mode)
    if mode_str is None:
        return (-1, errno.EINVAL)
    if "b" not in mode_str:
        mode_str = mode_str + "b"
    try:
        path_bytes = _semihost_read_exact(path_len)
    except SemihostReadError:
        raise
    except Exception:
        return (-1, errno.EIO)
    try:
        path = path_bytes.decode(errors="replace")
    except Exception:
        return (-1, errno.EINVAL)
    try:
        f = open(path, mode_str)
    except OSError as exc:
        return (-1, int(getattr(exc, "errno", errno.EIO)))
    try:
        handle = _semihost_alloc_handle()
    except Exception:
        try:
            f.close()
        except Exception:
            pass
        return (-1, errno.EIO)
    _semihost_files[handle] = f
    return (handle, 0)

def _semihost_write(info: Dict[str, str]) -> Tuple[int, int]:
    if "handle" not in info or "len" not in info:
        return (0, errno.EINVAL)
    try:
        handle = int(info["handle"], 0)
        total_len = int(info["len"], 0)
    except Exception:
        return (0, errno.EINVAL)
    f = _semihost_files.get(handle)
    if f is None:
        return (total_len, errno.EBADF)
    remaining = total_len
    try:
        while remaining > 0:
            read_len = min(HPSEMI_READ_CHUNK, remaining)
            chunk, _ = _semihost_read_chunk(read_len)
            if not chunk:
                raise SemihostReadError(remaining)
            f.write(chunk)
            remaining -= len(chunk)
        f.flush()
    except OSError as exc:
        return (remaining, int(getattr(exc, "errno", errno.EIO)))
    return (0, 0)

def _semihost_close(info: Dict[str, str]) -> Tuple[int, int]:
    if "handle" not in info:
        return (-1, errno.EINVAL)
    try:
        handle = int(info["handle"], 0)
    except Exception:
        return (-1, errno.EINVAL)
    f = _semihost_files.pop(handle, None)
    if f is None:
        return (-1, errno.EBADF)
    try:
        f.close()
    except OSError as exc:
        return (-1, int(getattr(exc, "errno", errno.EIO)))
    return (0, 0)

def _semihost_close_all() -> None:
    for handle, f in list(_semihost_files.items()):
        try:
            f.close()
        except Exception:
            pass
        _semihost_files.pop(handle, None)

def _semihost_handle_stop() -> bool:
    global _semihost_busy
    if _semihost_busy:
        return False
    _semihost_busy = True
    try:
        query = _semihost_query()
        if not query:
            return False
        op = query.get("op", 0)
        op_name = _SEMIHOST_OPS.get(op)
        if op_name is None:
            _semihost_reply(-1, errno.ENOSYS)
            gdb.execute("continue")
            return True
        info = _semihost_info()
        if op_name == "write0":
            try:
                text = _semihost_read_write0()
            except SemihostReadError:
                _semihost_reply(-1, errno.EIO)
                return True
            gdb.write(text)
            _semihost_reply(0, 0)
            gdb.execute("continue")
            return True
        if op_name == "open":
            try:
                handle, err = _semihost_open(info)
            except SemihostReadError:
                _semihost_reply(-1, errno.EIO)
                return True
            _semihost_reply(handle, err)
            gdb.execute("continue")
            return True
        if op_name == "write":
            try:
                result, err = _semihost_write(info)
            except SemihostReadError as exc:
                not_written = exc.remaining
                if not_written is None:
                    not_written = int(info.get("len", "0"), 0)
                _semihost_reply(not_written, errno.EIO)
                return True
            _semihost_reply(result, err)
            gdb.execute("continue")
            return True
        if op_name == "close":
            result, err = _semihost_close(info)
            _semihost_reply(result, err)
            gdb.execute("continue")
            return True
        _semihost_reply(-1, errno.ENOSYS)
        gdb.execute("continue")
        return True
    except Exception as exc:
        gdb.write(f"(semihost) error: {exc}\n")
        return False
    finally:
        _semihost_busy = False

def _bt_meta() -> Optional[Dict[str, object]]:
    try:
        out = _monitor("hp vbar bt?").strip()
    except Exception:
        return None
    if not out or out.startswith("none"):
        return None
    kv = _parse_kv(out)
    if "depth" not in kv:
        return None
    try:
        depth = int(kv.get("depth", "0"), 0)
        seq = int(kv.get("seq", "0"), 0)
        ver = int(kv.get("version", "0"), 0)
    except Exception:
        return None
    return {"seq": seq, "depth": depth, "version": ver, "raw": out}

def _bt_frames() -> List[Dict[str, int]]:
    out = _monitor("hp vbar bt")
    kv = _parse_kv(out)
    m = _data_re.search(out)
    if not m:
        raise RuntimeError("hp vbar bt: missing data")
    data_hex = m.group(1)
    try:
        depth = int(kv.get("depth", "0"), 0)
        stride = int(kv.get("stride", "56"), 0)
        ver = int(kv.get("version", "0"), 0)
    except Exception as e:
        raise RuntimeError(f"hp vbar bt parse failed: {e}")
    if ver != 1 or depth <= 0:
        return []
    blob = bytes.fromhex(data_hex)
    need = depth * stride
    if len(blob) < need:
        raise RuntimeError("hp vbar bt truncated")
    fmt = "<7Q"
    sz = struct.calcsize(fmt)
    frames = []
    for i in range(depth):
        off = i * stride
        pc, sp, fp, lr, spsr, esr, far = struct.unpack_from(fmt, blob, off)
        frames.append(
            {"pc": pc, "sp": sp, "fp": fp, "lr": lr, "spsr": spsr, "esr": esr, "far": far, "index": i}
        )
    return frames

# ----------------------------
# DWARF resolution
# ----------------------------

def _read_u64_le(addr: int) -> int:
    inferior = gdb.selected_inferior()
    mem = inferior.read_memory(addr, 8)
    return int.from_bytes(mem.tobytes(), "little", signed=False)

def _resolve_for_line(pc: int, is_lr: bool) -> int:
    if is_lr and HPBT_ADJUST_LR_FOR_RESOLVE and pc >= 4:
        return pc - 4
    return pc

def _dwarf_file_line(pc: int) -> Optional[Tuple[str, int]]:
    try:
        sal = gdb.find_pc_line(pc)
    except Exception:
        return None
    if not sal or not getattr(sal, "symtab", None) or getattr(sal, "line", 0) <= 0:
        return None
    symtab = sal.symtab
    line = int(sal.line)
    try:
        path = symtab.fullname()
    except Exception:
        path = getattr(symtab, "filename", None)
    if not path:
        return None
    return (path, line)

def _dwarf_function(pc: int) -> Optional[str]:
    try:
        blk = gdb.block_for_pc(pc)
    except Exception:
        blk = None
    while blk and getattr(blk, "function", None) is None:
        blk = getattr(blk, "superblock", None)
    fn = getattr(blk, "function", None) if blk else None
    if fn is None:
        return None
    name = getattr(fn, "print_name", None) or getattr(fn, "name", None)
    return str(name) if name else None

def _symbol_fallback(pc: int) -> Optional[str]:
    try:
        s = gdb.execute(f"info symbol 0x{pc:x}", to_string=True).strip()
        if not s or s.startswith("No symbol matches"):
            return None
        return s
    except Exception:
        return None

def _describe_pc(pc_raw: int, is_lr: bool) -> Tuple[str, Optional[str], Optional[int], bool]:
    pc = _resolve_for_line(pc_raw, is_lr)
    fn = _dwarf_function(pc)
    fl = _dwarf_file_line(pc)
    file = fl[0] if fl else None
    line = fl[1] if fl else None
    if fn or file:
        return (fn or "??", file, line, True)
    sym = _symbol_fallback(pc)
    if sym:
        return (sym, None, None, True)
    return ("??", None, None, False)

# ----------------------------
# Origin FP walk
# ----------------------------

def _format_frame(idx: int, pc_raw: int, fp: int, is_lr: bool) -> Tuple[str, bool]:
    fn, file, line, ok = _describe_pc(pc_raw, is_lr)
    idx_s = _c(f"#{idx}", "gray")
    pc_s = _c(f"0x{pc_raw:x}", "yellow")
    fn_s = _c(fn, "green") if fn != "??" else _c(fn, "red")
    fp_s = _c(f"fp=0x{fp:x}", "dim")
    if file and line:
        loc_s = _c(f"{file}:{line}", "cyan")
        s = f"{idx_s}  {pc_s} in {fn_s} at {loc_s} ({fp_s})\n"
    elif file:
        loc_s = _c(f"{file}:?", "cyan")
        s = f"{idx_s}  {pc_s} in {fn_s} at {loc_s} ({fp_s})\n"
    else:
        s = f"{idx_s}  {pc_s} in {fn_s} ({fp_s})\n"
    return s, ok

def _print_origin_header(origin: Dict[str, int]) -> None:
    gdb.write(_c("\n=== HyprProbe origin backtrace (pre-exception context) ===\n", "bold", "magenta"))
    meta = (
        f"pc=0x{origin['pc']:x} sp=0x{origin['sp']:x} fp=0x{origin['fp']:x} lr=0x{origin['lr']:x} "
        f"esr=0x{origin['esr']:x} far=0x{origin['far']:x} spsr=0x{origin['spsr']:x}\n"
    )
    gdb.write(_c(meta, "dim"))

def _fp_walk_origin(origin: Dict[str, int]) -> None:
    pc0 = origin["pc"]
    fp0 = origin["fp"]
    gdb.write(_c("=== HyprProbe origin backtrace (FP walk; DWARF-resolved) ===\n", "magenta"))
    s0, ok0 = _format_frame(0, pc0, fp0, is_lr=False)
    gdb.write(s0)
    if HPBT_FP_STOP_ON_UNKNOWN_PC and not ok0:
        gdb.write(_c("(hpbt) stop: pc not resolvable (DWARF/symbol).\n", "red"))
        return
    fp = fp0
    last_fp = fp0
    visited = {fp0}
    for i in range(1, HPBT_FP_MAX_DEPTH + 1):
        if fp == 0:
            gdb.write(_c("(hpbt) fp=0, stop.\n", "red"))
            break
        if (fp % HPBT_FP_ALIGN) != 0:
            gdb.write(_c(f"(hpbt) fp not aligned (fp=0x{fp:x}), stop.\n", "red"))
            break
        try:
            prev_fp = _read_u64_le(fp)
            saved_lr = _read_u64_le(fp + 8)
        except Exception as e:
            gdb.write(_c(f"(hpbt) fp walk memory read failed at fp=0x{fp:x}: {e}\n", "red"))
            break
        if prev_fp in visited:
            gdb.write(_c(f"(hpbt) fp loop detected (prev_fp=0x{prev_fp:x}), stop.\n", "red"))
            break
        visited.add(prev_fp)
        if HPBT_FP_MONOTONIC_ASCENDING and prev_fp != 0 and prev_fp <= last_fp:
            gdb.write(_c(f"(hpbt) fp not monotonic (prev_fp=0x{prev_fp:x} <= fp=0x{last_fp:x}), stop.\n", "red"))
            break
        s, ok = _format_frame(i, saved_lr, prev_fp, is_lr=True)
        gdb.write(s)
        if HPBT_FP_STOP_ON_UNKNOWN_PC and not ok:
            gdb.write(_c("(hpbt) stop: pc not resolvable (DWARF) FP chain corrupted.\n", "red"))
            break
        last_fp = prev_fp
        fp = prev_fp

# ----------------------------
# Public entry
# ----------------------------

def after_backtrace(bt_args: str = "") -> None:
    global _hpbt_busy
    if _hpbt_busy:
        return
    _hpbt_busy = True
    try:
        meta = _bt_meta()
        if not meta or int(meta["depth"]) < 1:
            return
        frames = _bt_frames()
        if not frames:
            return
        try:
            origin = frames[HPBT_ORIGIN_INDEX]
        except Exception:
            origin = frames[0]
        _print_origin_header(origin)
        _fp_walk_origin(origin)
    except Exception as e:
        gdb.write(_c(f"(hpbt) error: {e}\n", "red"))
    finally:
        _force_ansi_reset()
        _hpbt_busy = False

class HpBt(gdb.Command):
    """hpbt: Print HyprProbe origin backtrace (no register writes)."""

    def __init__(self) -> None:
        super(HpBt, self).__init__("hpbt", gdb.COMMAND_STACK)

    def invoke(self, arg: str, from_tty: bool) -> None:
        after_backtrace(arg.strip())

HpBt()

def _on_stop(event) -> None:
    if HPSEMI_AUTO_ON_STOP:
        if _semihost_handle_stop():
            return
    if not HPBT_AUTO_ON_STOP_IF_PRESENT:
        return
    try:
        meta = _bt_meta()
        if meta and int(meta["depth"]) >= 1:
            after_backtrace("")
    except Exception:
        pass

gdb.events.stop.connect(_on_stop)

def _on_exit(event) -> None:
    _semihost_close_all()

def _on_before_prompt(event) -> None:
    try:
        inf = gdb.selected_inferior()
    except Exception:
        inf = None
    if inf is None or getattr(inf, "pid", 0) == 0:
        _semihost_close_all()

gdb.events.exited.connect(_on_exit)
gdb.events.before_prompt.connect(_on_before_prompt)
