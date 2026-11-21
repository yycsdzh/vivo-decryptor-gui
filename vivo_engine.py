#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vivo Suite / PC Backup Decryption Engine (AES-256-GCM / CTR per-record IV).

Streaming decryption and extraction engine for vivo backup containers.
Never logs or prints passwords or derived keys.
"""

import base64
import json
import os
import re
import shutil
import struct
import tempfile

CHUNK_SIZE = 1 << 20  # 1 MiB streaming chunk size
MAX_RECORD_LEN = 200_000_000
AB_HEADER = b"ANDROID BACKUP\n5\n0\nnone\n"
AB_HEADER_LEN = len(AB_HEADER)  # 24 bytes
ZIP_LOCAL_SIG = b"PK\x03\x04"

INVALID_CHARS = set('<>:"|?*\\\'')
RESERVED_NAMES = (
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


class VivoDecryptError(Exception):
    """Base exception for vivo backup decryption errors."""


class WrongPasswordError(VivoDecryptError):
    """Raised when the backup password fails AES-GCM authentication."""


class CancelledError(VivoDecryptError):
    """Raised when an operation is cancelled via cancel_event."""


class InsufficientSpaceError(VivoDecryptError):
    """Raised when free disk space is insufficient for decryption/extraction."""


# ------------------------------------------------------------------ Helpers ---

def _log(log_cb, message):
    if log_cb is not None:
        log_cb(message)


def _progress(progress_cb, current, total, message=""):
    if progress_cb is not None:
        progress_cb(current, total, message)


def _check_cancel(cancel_event):
    if cancel_event is not None and cancel_event.is_set():
        raise CancelledError("Operation cancelled by user.")


def b64decode(s):
    """Base64 decode with automatic '=' padding."""
    return base64.b64decode(s + "=" * ((4 - len(s) % 4) % 4))


def check_free_space(target_dir, required_bytes):
    """Verify target_dir's filesystem has at least required_bytes free."""
    check_path = os.path.abspath(target_dir)
    while not os.path.exists(check_path):
        parent = os.path.dirname(check_path)
        if parent == check_path:
            break
        check_path = parent
    usage = shutil.disk_usage(check_path)
    if usage.free < required_bytes:
        raise InsufficientSpaceError(
            f"Insufficient free disk space at {check_path}: "
            f"need {required_bytes / (1024 ** 2):.1f} MiB, "
            f"available {usage.free / (1024 ** 2):.1f} MiB."
        )
    return usage.free


# --------------------------------------------------------------- Key Chain ---

def load_metadata(backup_dir):
    """Read plaintext `metadata` JSON from backup_dir."""
    path = os.path.join(backup_dir, "metadata")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def derive_keys(password, metadata):
    """Derive 32-byte content key K from password and metadata JSON.

    KEK = PBKDF2-HMAC-SHA256(password UTF-8, salt=d5, iterations=10000, length=32)
    d1  = 60 bytes: nonce(12) + ciphertext(32) + tag(16)
    K   = AESGCM(KEK).decrypt(nonce=d1[:12], ct_tag=d1[12:], None)

    Raises WrongPasswordError on InvalidTag.
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    d1 = b64decode(metadata["d1"])
    d5 = b64decode(metadata["d5"])
    if len(d1) != 60:
        raise VivoDecryptError(f"Unexpected d1 length: {len(d1)} (expected 60)")

    kek = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=d5,
        iterations=10000,
    ).derive(password.encode("utf-8"))

    nonce, ct_tag = d1[:12], d1[12:]
    try:
        key = AESGCM(kek).decrypt(nonce, ct_tag, None)
    except InvalidTag as exc:
        raise WrongPasswordError("Wrong password.") from exc
    return key


# -------------------------------------------------------------- Containers ---

def list_containers(backup_dir):
    """List sorted container base names in common/ excluding .xml, .nomedia, dotfiles."""
    common = os.path.join(backup_dir, "common")
    if not os.path.isdir(common):
        return []
    bases = set()
    for fn in os.listdir(common):
        if fn.endswith(".xml") or fn.endswith(".nomedia") or fn.startswith("."):
            continue
        bases.add(re.sub(r"__sub\d+$", "", fn))
    return sorted(bases)


def list_sub_parts(backup_dir, container):
    """Return all split parts for container: [name, name__sub1, name__sub2, ...]."""
    common = os.path.join(backup_dir, "common")
    parts = []
    base_path = os.path.join(common, container)
    if os.path.exists(base_path):
        parts.append(container)
    i = 1
    while os.path.exists(os.path.join(common, f"{container}__sub{i}")):
        parts.append(f"{container}__sub{i}")
        i += 1
    return parts


def get_container_size(backup_dir, container):
    """Return total encrypted byte size across all sub-parts of container."""
    common = os.path.join(backup_dir, "common")
    total = 0
    for part in list_sub_parts(backup_dir, container):
        path = os.path.join(common, part)
        if os.path.isfile(path):
            total += os.path.getsize(path)
    return total


def iter_decrypted_chunks(
    backup_dir,
    container,
    K,
    chunk_size=CHUNK_SIZE,
    progress_cb=None,
    cancel_event=None,
):
    """Stream decrypted plaintext chunks for all records in container.

    Record format: [4-byte big-endian length][12-byte iv][ciphertext + 16-byte tag]
    Each record uses its own iv with AES-256-CTR starting at counter = iv + 0x00000002,
    decrypting ct[:-16] only (tag ignored).
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    common = os.path.join(backup_dir, "common")
    total_bytes = get_container_size(backup_dir, container)
    done_bytes = 0

    for part in list_sub_parts(backup_dir, container):
        path = os.path.join(common, part)
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            off = 0
            while off < size:
                _check_cancel(cancel_event)
                f.seek(off)
                hdr = f.read(16)
                if len(hdr) < 16:
                    break
                ln = struct.unpack(">I", hdr[:4])[0]
                iv = hdr[4:16]
                if ln <= 16 or ln > MAX_RECORD_LEN:
                    break
                if off + 16 + ln > size:
                    break

                ct_len = ln - 16
                counter = iv + b"\x00\x00\x00\x02"
                decryptor = Cipher(algorithms.AES(K), modes.CTR(counter)).decryptor()

                remaining = ct_len
                while remaining > 0:
                    _check_cancel(cancel_event)
                    raw = f.read(min(chunk_size, remaining))
                    if not raw:
                        break
                    plain = decryptor.update(raw)
                    remaining -= len(raw)
                    done_bytes += len(raw)
                    if plain:
                        yield plain
                    _progress(progress_cb, done_bytes, total_bytes, f"Decrypting {container}")

                final_chunk = decryptor.finalize()
                if final_chunk:
                    yield final_chunk

                off += 16 + ln
                done_bytes += 32  # 16-byte header + 16-byte ignored tag
                _progress(
                    progress_cb,
                    min(done_bytes, total_bytes),
                    total_bytes,
                    f"Decrypting {container}",
                )


def decrypt_container_to_temp(
    backup_dir,
    container,
    K,
    progress_cb=None,
    cancel_event=None,
    temp_dir=None,
):
    """Decrypt container stream to a temporary file and return its path.

    Caller is responsible for removing the returned temporary file when done.
    """
    est_size = get_container_size(backup_dir, container)
    target_tmp_dir = temp_dir or tempfile.gettempdir()
    os.makedirs(target_tmp_dir, exist_ok=True)
    check_free_space(target_tmp_dir, est_size)

    tmp_fd, tmp_path = tempfile.mkstemp(
        prefix=f"vivo_{container}_",
        suffix=".tmp",
        dir=target_tmp_dir,
    )
    try:
        with os.fdopen(tmp_fd, "wb") as tmp:
            for chunk in iter_decrypted_chunks(
                backup_dir,
                container,
                K,
                progress_cb=progress_cb,
                cancel_event=cancel_event,
            ):
                tmp.write(chunk)
        return tmp_path
    except Exception:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        raise


def detect_container_type(path):
    """Detect whether decrypted container file is 'tar' (.ab) or 'zip' (stream ZIP)."""
    with open(path, "rb") as f:
        head = f.read(32)
    if head.startswith(b"ANDROID BACKUP"):
        return "tar"
    return "zip"


# --------------------------------------------------------- Name Sanitization ---

def sanitize_name(name):
    """Sanitize a tar/zip entry name into a safe relative path for Windows/POSIX.

    - Replaces illegal Windows characters and control chars with '_'
    - Strips trailing dots and spaces from each segment
    - Prefixes Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9) with '_'
    - Drops empty, '.', and '..' segments to prevent path traversal
    """
    name = name.replace("\\", "/")
    name = "".join(
        "_" if (c in INVALID_CHARS or ord(c) < 32 or ord(c) == 127) else c
        for c in name
    )

    parts = []
    for part in name.split("/"):
        if part in ("", ".", ".."):
            continue
        part = part.rstrip(". ")
        if not part:
            continue
        if part.split(".")[0].upper() in RESERVED_NAMES:
            part = "_" + part
        parts.append(part)
    return "/".join(parts) if parts else None


def _safe_join(base_dir, rel_posix):
    """Join base_dir and sanitized POSIX relative path, verifying no traversal."""
    base_abs = os.path.abspath(base_dir)
    dest = os.path.abspath(os.path.join(base_abs, rel_posix.replace("/", os.sep)))
    if os.path.commonpath([base_abs, dest]) != base_abs:
        raise VivoDecryptError(f"Path traversal blocked: {rel_posix}")
    return dest


# --------------------------------------------------------------- Tar Parsing ---

def tar_checksum_ok(hdr):
    """Verify ustar tar header checksum (hdr[148:156])."""
    if len(hdr) < 512:
        return False
    try:
        stored = int(hdr[148:156].split(b"\x00")[0].strip() or b"0", 8)
    except ValueError:
        return False
    total = sum(hdr[:148]) + sum(b" " * 8) + sum(hdr[156:])
    return stored == total


def _skip_exact(read_exact, nbytes, cancel_event=None):
    """Discard nbytes from read_exact in bounded chunks."""
    remaining = nbytes
    while remaining > 0:
        _check_cancel(cancel_event)
        chunk = read_exact(min(CHUNK_SIZE, remaining))
        if not chunk:
            return False
        remaining -= len(chunk)
    return True


def extract_tar_stream(
    read_exact,
    out_dir,
    selected_files=None,
    progress_cb=None,
    cancel_event=None,
    log_cb=None,
):
    """Parse an Android Backup (.ab) ustar tar stream and extract files in chunks.

    Does not hold whole files in memory.
    Returns (file_count, total_written_bytes).
    """
    os.makedirs(out_dir, exist_ok=True)
    selected_set = set(selected_files) if selected_files is not None else None
    n = 0
    wbytes = 0

    def stream_to_file(rel, size):
        nonlocal n, wbytes
        dest = _safe_join(out_dir, rel)
        fh = None
        fallback_used = False
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            fh = open(dest, "wb")
        except OSError as e:
            alt = os.path.join(out_dir, "_flat", f"{n}_{os.path.basename(rel) or 'x'}")
            try:
                os.makedirs(os.path.dirname(alt), exist_ok=True)
                fh = open(alt, "wb")
                fallback_used = True
                _log(log_cb, f"Fallback: {rel} -> _flat/{os.path.basename(alt)} ({e})")
            except OSError as e2:
                _log(log_cb, f"Write failed, skipped {rel} ({e2})")
                return _skip_exact(read_exact, size, cancel_event=cancel_event)

        written = 0
        try:
            remaining = size
            while remaining > 0:
                _check_cancel(cancel_event)
                chunk = read_exact(min(CHUNK_SIZE, remaining))
                if not chunk:
                    return False
                fh.write(chunk)
                written += len(chunk)
                remaining -= len(chunk)
        finally:
            fh.close()

        n += 1
        wbytes += written
        _progress(progress_cb, wbytes, 0, f"Extracted {rel}" + (" (_flat)" if fallback_used else ""))
        return True

    ab_hdr = read_exact(AB_HEADER_LEN)
    if len(ab_hdr) < AB_HEADER_LEN:
        return n, wbytes

    while True:
        _check_cancel(cancel_event)
        hdr = read_exact(512)
        if len(hdr) < 512:
            break
        if hdr == b"\x00" * 512:
            if read_exact(512) == b"\x00" * 512:
                break
            continue
        if not tar_checksum_ok(hdr):
            break

        raw_name = hdr[0:100].split(b"\x00")[0].decode("utf-8", "replace")
        prefix = hdr[345:500].split(b"\x00")[0].decode("utf-8", "replace")
        if prefix:
            raw_name = prefix + "/" + raw_name
        try:
            size = int(hdr[124:136].split(b"\x00")[0].strip() or b"0", 8)
        except ValueError:
            break
        typef = chr(hdr[156]) if hdr[156] else "0"
        rel = sanitize_name(raw_name)
        pad = (512 - size % 512) % 512

        want = (
            typef == "0"
            and rel is not None
            and (selected_set is None or rel in selected_set or raw_name in selected_set)
        )
        if want:
            if not stream_to_file(rel, size):
                break
            if pad and not _skip_exact(read_exact, pad, cancel_event=cancel_event):
                break
        else:
            total_skip = ((size + 511) // 512) * 512
            if total_skip and not _skip_exact(read_exact, total_skip, cancel_event=cancel_event):
                break

    return n, wbytes


def _stream_tar_from_records(
    backup_dir,
    container,
    K,
    out_dir,
    selected_files=None,
    progress_cb=None,
    cancel_event=None,
    log_cb=None,
):
    """Stream-decrypt tar container directly into extract_tar_stream with no temp file."""
    chunk_iter = iter_decrypted_chunks(
        backup_dir,
        container,
        K,
        progress_cb=progress_cb,
        cancel_event=cancel_event,
    )
    buf = bytearray()

    def read_exact(nb):
        while len(buf) < nb:
            _check_cancel(cancel_event)
            try:
                buf.extend(next(chunk_iter))
            except StopIteration:
                break
        out = bytes(buf[:nb])
        del buf[:nb]
        return out

    return extract_tar_stream(
        read_exact,
        out_dir,
        selected_files=selected_files,
        progress_cb=None,
        cancel_event=cancel_event,
        log_cb=log_cb,
    )


def _list_tar_entries(path, cancel_event=None):
    """Scan a decrypted .ab tar file and return entry metadata without loading file data."""
    entries = []
    fsize = os.path.getsize(path)
    with open(path, "rb") as fh:
        if fsize < AB_HEADER_LEN:
            return entries
        fh.seek(AB_HEADER_LEN)
        while fh.tell() + 512 <= fsize:
            _check_cancel(cancel_event)
            hdr = fh.read(512)
            if len(hdr) < 512:
                break
            if hdr == b"\x00" * 512:
                if fh.read(512) == b"\x00" * 512:
                    break
                continue
            if not tar_checksum_ok(hdr):
                break
            raw_name = hdr[0:100].split(b"\x00")[0].decode("utf-8", "replace")
            prefix = hdr[345:500].split(b"\x00")[0].decode("utf-8", "replace")
            if prefix:
                raw_name = prefix + "/" + raw_name
            try:
                size = int(hdr[124:136].split(b"\x00")[0].strip() or b"0", 8)
            except ValueError:
                break
            typef = chr(hdr[156]) if hdr[156] else "0"
            data_off = fh.tell()
            rel = sanitize_name(raw_name)
            if typef == "0" and rel:
                entries.append(
                    {
                        "name": rel,
                        "raw_name": raw_name,
                        "offset": data_off,
                        "size": size,
                    }
                )
            skip = ((size + 511) // 512) * 512
            fh.seek(data_off + skip)
    return entries


# --------------------------------------------------------- Stream ZIP Parsing ---

def valid_entry_name(name_b):
    """Filter false-positive PK headers: valid UTF-8 path containing '/' or '.'."""
    try:
        s = name_b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not s:
        return False
    if any(ord(c) < 32 for c in s):
        return False
    return "/" in s or "." in s


def _iter_stream_zip_entries(path, scan_chunk=CHUNK_SIZE, cancel_event=None):
    """Yield stream-ZIP entry dicts (name, raw_name, offset, size) without loading file data."""
    fsize = os.path.getsize(path)
    with open(path, "rb") as fh:
        pos = 0
        while pos < fsize:
            _check_cancel(cancel_event)
            fh.seek(pos)
            probe = fh.read(scan_chunk)
            if not probe:
                break
            idx = probe.find(ZIP_LOCAL_SIG)
            if idx == -1:
                if len(probe) < scan_chunk:
                    break
                pos += max(1, len(probe) - 3)
                continue

            hdr_off = pos + idx
            fh.seek(hdr_off)
            hdr = fh.read(30)
            if len(hdr) < 30:
                break
            flags = struct.unpack_from("<H", hdr, 6)[0]
            csize = struct.unpack_from("<I", hdr, 18)[0]
            nlen, elen = struct.unpack_from("<HH", hdr, 26)
            if not (1 <= nlen <= 8192 and elen <= 8192):
                pos = hdr_off + 1
                continue
            ne = fh.read(nlen + elen)
            if len(ne) < nlen + elen:
                break
            name_b = ne[:nlen]
            if not valid_entry_name(name_b):
                pos = hdr_off + 1
                continue

            raw_name = name_b.decode("utf-8", "replace")
            data_off = hdr_off + 30 + nlen + elen
            has_descr = bool(flags & 0x08)
            if has_descr or csize == 0:
                sp = data_off
                nxt = -1
                while sp < fsize:
                    _check_cancel(cancel_event)
                    fh.seek(sp)
                    blk = fh.read(scan_chunk)
                    if not blk:
                        break
                    j = blk.find(ZIP_LOCAL_SIG)
                    if j != -1:
                        nxt = sp + j
                        break
                    if len(blk) < scan_chunk:
                        break
                    sp += max(1, len(blk) - 3)
                if nxt == -1:
                    nxt = fsize
                csize = nxt - data_off
                if has_descr and csize >= 16:
                    csize -= 16

            csize = max(0, min(csize, fsize - data_off))
            rel = sanitize_name(raw_name)
            if not rel:
                pos = hdr_off + 1
                continue

            yield {
                "name": rel,
                "raw_name": raw_name,
                "offset": data_off,
                "size": csize,
            }
            pos = data_off + csize


def list_zip_entries(path, cancel_event=None):
    """List entries in a decrypted container temp file (stream-ZIP or .ab tar).

    Returns a list of dicts: {'name': sanitized_rel, 'raw_name': raw, 'offset': int, 'size': int}.
    """
    if detect_container_type(path) == "tar":
        return _list_tar_entries(path, cancel_event=cancel_event)
    return list(_iter_stream_zip_entries(path, cancel_event=cancel_event))


def _dump_range(fh, dest, data_off, csize, scan_chunk=CHUNK_SIZE, cancel_event=None):
    """Copy csize bytes from fh at data_off into dest in bounded chunks."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    fh.seek(data_off)
    written = 0
    remaining = csize
    with open(dest, "wb") as w:
        while remaining > 0:
            _check_cancel(cancel_event)
            chunk = fh.read(min(scan_chunk, remaining))
            if not chunk:
                break
            w.write(chunk)
            written += len(chunk)
            remaining -= len(chunk)
    return written


def extract_selected(
    temp_path,
    selected_names,
    out_dir,
    progress_cb=None,
    cancel_event=None,
    log_cb=None,
):
    """Extract selected entries from a decrypted temp container (stream-ZIP or .ab tar).

    If selected_names is None, extracts all entries.
    Returns (file_count, total_written_bytes).
    """
    os.makedirs(out_dir, exist_ok=True)
    selected_set = set(selected_names) if selected_names is not None else None

    if detect_container_type(temp_path) == "tar":
        with open(temp_path, "rb") as fh:
            return extract_tar_stream(
                fh.read,
                out_dir,
                selected_files=selected_set,
                progress_cb=progress_cb,
                cancel_event=cancel_event,
                log_cb=log_cb,
            )

    entries = list(_iter_stream_zip_entries(temp_path, cancel_event=cancel_event))
    if selected_set is not None:
        entries = [
            e for e in entries
            if e["name"] in selected_set or e["raw_name"] in selected_set
        ]

    total_bytes = sum(e["size"] for e in entries)
    check_free_space(out_dir, total_bytes)

    rec = 0
    wbytes = 0
    with open(temp_path, "rb") as fh:
        for entry in entries:
            _check_cancel(cancel_event)
            rel = entry["name"]
            dest = _safe_join(out_dir, rel)
            try:
                wbytes += _dump_range(
                    fh, dest, entry["offset"], entry["size"], cancel_event=cancel_event
                )
            except OSError as e:
                alt = os.path.join(out_dir, "_flat", f"{rec}_{os.path.basename(rel)}")
                try:
                    wbytes += _dump_range(
                        fh, alt, entry["offset"], entry["size"], cancel_event=cancel_event
                    )
                    _log(log_cb, f"Fallback: {rel} -> _flat/{os.path.basename(alt)} ({e})")
                except OSError as e2:
                    _log(log_cb, f"Write failed, skipped {rel} ({e2})")
                    continue
            rec += 1
            _progress(progress_cb, wbytes, total_bytes, f"Extracted {rel}")

    return rec, wbytes


def parse_stream_zip(
    path,
    out_dir,
    scan_chunk=CHUNK_SIZE,
    progress_cb=None,
    cancel_event=None,
    log_cb=None,
):
    """Parse stream-ZIP file and extract all entries into out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    fsize = os.path.getsize(path)
    rec = 0
    wbytes = 0
    with open(path, "rb") as fh:
        for entry in _iter_stream_zip_entries(path, scan_chunk=scan_chunk, cancel_event=cancel_event):
            _check_cancel(cancel_event)
            rel = entry["name"]
            dest = _safe_join(out_dir, rel)
            try:
                wbytes += _dump_range(
                    fh,
                    dest,
                    entry["offset"],
                    entry["size"],
                    scan_chunk=scan_chunk,
                    cancel_event=cancel_event,
                )
            except OSError as e:
                alt = os.path.join(out_dir, "_flat", f"{rec}_{os.path.basename(rel)}")
                try:
                    wbytes += _dump_range(
                        fh,
                        alt,
                        entry["offset"],
                        entry["size"],
                        scan_chunk=scan_chunk,
                        cancel_event=cancel_event,
                    )
                    _log(log_cb, f"Fallback: {rel} -> _flat/{os.path.basename(alt)} ({e})")
                except OSError as e2:
                    _log(log_cb, f"Write failed, skipped {rel} ({e2})")
                    continue
            rec += 1
            _progress(progress_cb, min(wbytes, fsize), fsize, f"Extracted {rel}")
    return rec, wbytes


# ------------------------------------------------------------ Main Workflow ---

def _detect_encrypted_container_type(backup_dir, container, K):
    """Peek the first decrypted chunk of a container to detect 'tar' vs 'zip'."""
    for chunk in iter_decrypted_chunks(backup_dir, container, K, chunk_size=4096):
        if chunk.startswith(b"ANDROID BACKUP"):
            return "tar"
        return "zip"
    return "zip"


def decrypt_backup(
    backup_dir,
    out_dir,
    password,
    only=None,
    selected_files=None,
    progress_cb=None,
    cancel_event=None,
    log_cb=None,
):
    """Decrypt a vivo backup directory into out_dir.

    - only: optional container name (str) or iterable of container names to decrypt
    - selected_files: optional iterable of entry names, or dict {container: iterable}
    - progress_cb: optional callable(current, total, message)
    - cancel_event: optional threading.Event-like object
    - log_cb: optional callable(message)

    Returns summary dict: {'files': int, 'bytes': int, 'containers': dict}.
    Never logs or prints the password or key K.
    """
    _check_cancel(cancel_event)
    metadata = load_metadata(backup_dir)
    K = derive_keys(password, metadata)
    _log(log_cb, "Backup key derived successfully.")

    containers = list_containers(backup_dir)
    if only is not None:
        if isinstance(only, str):
            only_set = {only}
        else:
            only_set = set(only)
        containers = [c for c in containers if c in only_set]

    total_enc_size = sum(get_container_size(backup_dir, c) for c in containers)
    os.makedirs(out_dir, exist_ok=True)
    check_free_space(out_dir, total_enc_size)

    grand_n = 0
    grand_b = 0
    results = {}

    for idx, container in enumerate(containers, 1):
        _check_cancel(cancel_event)
        _log(log_cb, f"[{idx}/{len(containers)}] Processing container: {container}")
        sub_out = os.path.join(out_dir, container)
        os.makedirs(sub_out, exist_ok=True)

        if isinstance(selected_files, dict):
            container_selected = selected_files.get(container)
            if container_selected is None:
                continue
        else:
            container_selected = selected_files

        kind = _detect_encrypted_container_type(backup_dir, container, K)
        if kind == "tar":
            n, w = _stream_tar_from_records(
                backup_dir,
                container,
                K,
                sub_out,
                selected_files=container_selected,
                progress_cb=progress_cb,
                cancel_event=cancel_event,
                log_cb=log_cb,
            )
        else:
            tmp_path = decrypt_container_to_temp(
                backup_dir,
                container,
                K,
                progress_cb=progress_cb,
                cancel_event=cancel_event,
                temp_dir=out_dir,
            )
            try:
                if container_selected is not None:
                    n, w = extract_selected(
                        tmp_path,
                        container_selected,
                        sub_out,
                        progress_cb=progress_cb,
                        cancel_event=cancel_event,
                        log_cb=log_cb,
                    )
                else:
                    n, w = parse_stream_zip(
                        tmp_path,
                        sub_out,
                        progress_cb=progress_cb,
                        cancel_event=cancel_event,
                        log_cb=log_cb,
                    )
            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass

        grand_n += n
        grand_b += w
        results[container] = {"kind": kind, "files": n, "bytes": w}
        _log(log_cb, f"  {container} ({kind}): {n} files / {w / 1e6:.1f} MB")

    _log(log_cb, f"Done: {grand_n} files / {grand_b / 1e6:.1f} MB")
    return {"files": grand_n, "bytes": grand_b, "containers": results}
