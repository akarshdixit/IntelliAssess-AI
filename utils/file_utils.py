"""
utils/file_utils.py
===================
Low-level file and directory utilities for IntelliAssess AI.

No business logic. Pure I/O helpers used by core/, parsers/, and reporting/.

These functions are defensive: they never silently overwrite or lose data.
"""

import hashlib
import shutil
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

log = get_logger(__name__)


def ensure_dir(path: Path) -> Path:
    """Create directory (and parents) if it does not exist. Returns the path."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_dirs(*paths: Path) -> None:
    """Create multiple directories, ignoring those that already exist."""
    for p in paths:
        ensure_dir(p)


def safe_move(src: Path, dst_dir: Path, overwrite: bool = False) -> Optional[Path]:
    """
    Move src file into dst_dir.

    If a file with the same name already exists in dst_dir:
      - overwrite=False (default): skip and return None
      - overwrite=True: overwrite and return destination path

    Returns:
        Destination Path on success, None on skip/failure.
    """
    if not src.exists():
        log.warning("safe_move: source does not exist: %s", src)
        return None

    ensure_dir(dst_dir)
    dst = dst_dir / src.name

    if dst.exists() and not overwrite:
        log.debug("safe_move: destination exists, skipping: %s", dst)
        return None

    shutil.move(str(src), str(dst))
    log.debug("safe_move: %s → %s", src, dst)
    return dst


def file_sha256(path: Path) -> str:
    """Return the SHA-256 hex digest of a file. Used for deduplication checks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_text_safe(path: Path, content: str, encoding: str = "utf-8") -> bool:
    """
    Write text to path atomically (write to .tmp, then rename).

    Prevents partial writes from corrupting session.json or report files.
    Returns True on success, False on failure.
    """
    tmp = path.with_suffix(".tmp")
    try:
        ensure_dir(path.parent)
        tmp.write_text(content, encoding=encoding)
        tmp.replace(path)
        return True
    except OSError as exc:
        log.error("write_text_safe failed for %s: %s", path, exc)
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        return False


def read_text_safe(path: Path, encoding: str = "utf-8") -> Optional[str]:
    """
    Read text from path. Returns None on any I/O error rather than raising.
    Caller decides how to handle missing/corrupt files.
    """
    try:
        return path.read_text(encoding=encoding)
    except OSError as exc:
        log.error("read_text_safe failed for %s: %s", path, exc)
        return None
