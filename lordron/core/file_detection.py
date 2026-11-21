"""
File format identification and magic signature inspection engine.
Does not trust file extensions; inspects raw byte signatures.
"""

from __future__ import annotations
import platform
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List
from lordron.core.paths import validate_file_path
from lordron.core.exceptions import FileAccessError

# Comprehensive forensic signatures table: (magic_bytes, offset, format_name, mime_type, standard_extensions)
SIGNATURES: List[tuple[bytes, int, str, str, tuple[str, ...]]] = [
    # Executables & Binaries
    (b"\x7fELF", 0, "ELF Executable/Object", "application/x-executable", (".elf", ".so", ".bin")),
    (b"MZ", 0, "Windows PE Executable / DLL", "application/x-dosexec", (".exe", ".dll", ".sys", ".scr")),
    (b"\xca\xfe\xba\xbe", 0, "Mach-O Universal Binary / Java Class", "application/x-mach-binary", (".dylib", ".class", ".bin")),
    (b"\xfe\xed\xfa\xce", 0, "Mach-O 32-bit (BE)", "application/x-mach-binary", (".dylib", ".bin")),
    (b"\xfe\xed\xfa\xcf", 0, "Mach-O 64-bit (BE)", "application/x-mach-binary", (".dylib", ".bin")),
    (b"\xce\xfa\xed\xfe", 0, "Mach-O 32-bit (LE)", "application/x-mach-binary", (".dylib", ".bin")),
    (b"\xcf\xfa\xed\xfe", 0, "Mach-O 64-bit (LE)", "application/x-mach-binary", (".dylib", ".bin")),
    (b"\x00asm", 0, "WebAssembly Binary", "application/wasm", (".wasm",)),
    (b"dex\n", 0, "Android Dalvik Executable", "application/vnd.android.dex", (".dex",)),

    # Archives & Compressed
    (b"PK\x03\x04", 0, "ZIP Archive / OpenDocument / Office OpenXML", "application/zip", (".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx")),
    (b"PK\x05\x06", 0, "Empty ZIP Archive", "application/zip", (".zip",)),
    (b"PK\x07\x08", 0, "Spanned ZIP Archive", "application/zip", (".zip",)),
    (b"\x1f\x8b\x08", 0, "GZIP Compressed Archive", "application/gzip", (".gz", ".tgz")),
    (b"BZh", 0, "BZIP2 Compressed File", "application/x-bzip2", (".bz2",)),
    (b"\xfd7zXZ\x00", 0, "XZ Compressed Archive", "application/x-xz", (".xz",)),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip Archive", "application/x-7z-compressed", (".7z",)),
    (b"Rar!\x1a\x07\x00", 0, "RAR Archive (v4)", "application/x-rar-compressed", (".rar",)),
    (b"Rar!\x1a\x07\x01\x00", 0, "RAR Archive (v5)", "application/x-rar-compressed", (".rar",)),
    (b"\x28\xb5\x2f\xfd", 0, "Zstandard Compressed File", "application/zstd", (".zst",)),
    (b"ustar", 257, "TAR Archive (POSIX)", "application/x-tar", (".tar",)),

    # Documents
    (b"%PDF-", 0, "PDF Document", "application/pdf", (".pdf",)),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "Microsoft Compound File (OLE2 / legacy Office)", "application/x-ole-storage", (".doc", ".xls", ".ppt", ".msg")),
    (b"{\\rtf", 0, "Rich Text Format (RTF)", "application/rtf", (".rtf",)),

    # Images
    (b"\x89PNG\r\n\x1a\n", 0, "PNG Image", "image/png", (".png",)),
    (b"\xff\xd8\xff", 0, "JPEG Image", "image/jpeg", (".jpg", ".jpeg", ".jpe")),
    (b"GIF87a", 0, "GIF87a Image", "image/gif", (".gif",)),
    (b"GIF89a", 0, "GIF89a Image", "image/gif", (".gif",)),
    (b"BM", 0, "BMP Image", "image/bmp", (".bmp",)),
    (b"II*\x00", 0, "TIFF Image (Little-Endian)", "image/tiff", (".tif", ".tiff")),
    (b"MM\x00*", 0, "TIFF Image (Big-Endian)", "image/tiff", (".tif", ".tiff")),
    (b"RIFF", 0, "RIFF Container (WEBP / WAV / AVI)", "application/octet-stream", (".webp", ".wav", ".avi")),

    # Audio & Video
    (b"ID3", 0, "MP3 Audio (with ID3v2 container)", "audio/mpeg", (".mp3",)),
    (b"\xff\xfb", 0, "MPEG-1 Layer 3 (MP3 raw)", "audio/mpeg", (".mp3",)),
    (b"OggS", 0, "OGG Media Stream", "audio/ogg", (".ogg", ".oga", ".ogv")),
    (b"\x1a\x45\xdf\xa3", 0, "Matroska / MKV / WebM Video", "video/x-matroska", (".mkv", ".webm")),
    (b"FLV\x01", 0, "Flash Video", "video/x-flv", (".flv",)),
    (b"ftyp", 4, "ISO Media / MP4 / M4A / MOV", "video/mp4", (".mp4", ".m4a", ".mov")),

    # Databases & Forensics
    (b"SQLite format 3\x00", 0, "SQLite 3 Database", "application/vnd.sqlite3", (".db", ".sqlite", ".sqlite3")),
    (b"\xd4\xc3\xb2\xa1", 0, "PCAP Packet Capture (LE)", "application/vnd.tcpdump.pcap", (".pcap",)),
    (b"\xa1\xb2\xc3\xd4", 0, "PCAP Packet Capture (BE)", "application/vnd.tcpdump.pcap", (".pcap",)),
    (b"\n\r\r\n", 0, "PCAP Next Generation Capture (PCAPNG)", "application/x-pcapng", (".pcapng",)),
    (b"regf", 0, "Windows Registry Hive File", "application/x-windows-registry", (".dat", ".hiv")),
    (b"evtx", 0, "Windows Event Log (EVTX)", "application/x-ms-evtx", (".evtx",)),
]


def detect_magic_signature(header: bytes) -> Optional[tuple[str, str, tuple[str, ...]]]:
    """Inspect byte slice against the forensics signatures table."""
    for magic, offset, fmt_name, mime_type, extensions in SIGNATURES:
        end = offset + len(magic)
        if len(header) >= end and header[offset:end] == magic:
            # Special check for RIFF subtypes
            if magic == b"RIFF" and len(header) >= 12:
                sub = header[8:12]
                if sub == b"WEBP":
                    return ("WebP Image", "image/webp", (".webp",))
                elif sub == b"WAVE":
                    return ("WAV Audio", "audio/wav", (".wav",))
                elif sub == b"AVI ":
                    return ("AVI Video", "video/x-msvideo", (".avi",))
            return (fmt_name, mime_type, extensions)
    return None


def inspect_file(file_path: str | Path) -> Dict[str, Any]:
    """
    Perform a complete non-executing file inspection:
    - True signature inspection
    - MIME type deduction
    - Size and timestamps in UTC
    - Suspicious extension mismatch detection
    """
    path = validate_file_path(file_path, must_exist=True)
    if not path.is_file():
        raise FileAccessError(f"Target '{path}' is not a regular file.")

    stat = path.stat()
    file_size = stat.st_size
    extension = path.suffix.lower()

    # Read up to 512 bytes for signature matching without reading full file into memory
    header = b""
    try:
        with open(path, "rb") as f:
            header = f.read(512)
    except OSError as exc:
        raise FileAccessError(f"Cannot read file header '{path}': {exc}") from exc

    sig_match = detect_magic_signature(header)
    guessed_mime, _ = mimetypes.guess_type(str(path))

    if sig_match:
        detected_format, detected_mime, valid_exts = sig_match
        is_known_signature = True
    else:
        detected_format = "Unknown Binary or Plaintext"
        detected_mime = guessed_mime or "application/octet-stream"
        valid_exts = ()
        is_known_signature = False

        # Check if text
        try:
            sample = header[:128].decode("utf-8")
            if sample.isprintable() or "\n" in sample or "\r" in sample:
                detected_format = "Plaintext / Script File"
                detected_mime = guessed_mime or "text/plain"
        except UnicodeDecodeError:
            pass

    # Check for extension mismatch anomaly
    is_suspicious_mismatch = False
    mismatch_details = None

    if is_known_signature and valid_exts:
        if extension not in valid_exts and extension != "":
            # E.g. an ELF or PE disguised as .jpg or .pdf
            is_suspicious_mismatch = True
            mismatch_details = (
                f"File extension '{extension}' contradicts detected signature '{detected_format}'. "
                f"Expected one of: {', '.join(valid_exts)}"
            )

    # Format timestamps
    mtime_utc = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
    ctime_utc = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()
    atime_utc = datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat()

    timestamps: dict[str, str] = {
        "modified_utc": mtime_utc,
        "created_or_metadata_changed_utc": ctime_utc,
        "accessed_utc": atime_utc,
    }
    # Check for true birthtime if exposed by filesystem (macOS/BSD) or Windows creation time
    if hasattr(stat, "st_birthtime"):
        timestamps["birthtime_utc"] = datetime.fromtimestamp(stat.st_birthtime, tz=timezone.utc).isoformat()
    elif platform.system() == "Windows":
        timestamps["created_utc"] = ctime_utc

    return {
        "file_name": path.name,
        "absolute_path": str(path),
        "file_size_bytes": file_size,
        "extension": extension or "(none)",
        "detected_format": detected_format,
        "mime_type": detected_mime,
        "known_signature": is_known_signature,
        "header_hex_preview": header[:32].hex(" "),
        "suspicious_mismatch": is_suspicious_mismatch,
        "mismatch_details": mismatch_details,
        "timestamps": timestamps,
    }
