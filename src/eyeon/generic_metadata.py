"""EyeON-owned fallback metadata for files without deep format plugins."""

from __future__ import annotations

import mimetypes
import os
from pathlib import Path
from typing import Optional


def generic_metadata(
    file: str,
    *,
    filename: str,
    bytecount: int,
    magic: str,
    identify_error: Optional[str] = None,
) -> dict:
    """Return fallback metadata for files without a format-specific extractor."""

    path = Path(file)
    extension = path.suffix.lower()
    base = {
        "extension": extension,
        "magic": magic,
        "mime_type": mimetypes.guess_type(filename)[0],
        "is_empty": bytecount == 0,
    }
    if identify_error:
        base["identify_error"] = identify_error

    if os.path.islink(file):
        return {
            "symlink_file": {
                **base,
                "target": os.readlink(file),
            }
        }

    opkg_kind = _opkg_kind(extension)
    if opkg_kind:
        return {
            "opkg_file": {
                **base,
                "kind": opkg_kind,
                "package": _package_name(path, extension),
                **_text_summary(file),
                **_opkg_control_fields(file, opkg_kind),
            }
        }

    if _is_device_tree(extension, magic):
        return {"device_tree_file": {**base, "kind": "device-tree"}}

    if _is_linux_kernel_image(magic):
        return {"linux_kernel_image": {**base, "kind": "linux-kernel-image"}}

    web_kind = _web_asset_kind(extension, magic)
    if web_kind:
        metadata = {**base, "kind": web_kind}
        if web_kind in {"html", "javascript", "css", "svg"}:
            metadata.update(_text_summary(file))
        return {"web_asset": metadata}

    image_kind = _image_kind(extension, magic)
    if image_kind:
        return {"image_file": {**base, "kind": image_kind}}

    text_kind = _text_kind(extension, magic)
    if text_kind:
        return {"text_file": {**base, "kind": text_kind, **_text_summary(file)}}

    return {"generic_file": {**base, "kind": "binary-blob" if magic == "data" else "unclassified"}}


def _opkg_kind(extension: str) -> Optional[str]:
    return {
        ".control": "control",
        ".list": "file-list",
        ".conffiles": "config-file-list",
        ".prerm": "script",
        ".postrm": "script",
        ".preinst": "script",
        ".postinst": "script",
    }.get(extension)


def _package_name(path: Path, extension: str) -> str:
    name = path.name
    if extension and name.endswith(extension):
        return name[: -len(extension)]
    return path.stem


def _is_device_tree(extension: str, magic: str) -> bool:
    return extension == ".dtb" or magic.startswith("Device Tree File")


def _is_linux_kernel_image(magic: str) -> bool:
    return "Linux kernel" in magic and "zImage" in magic


def _web_asset_kind(extension: str, magic: str) -> Optional[str]:
    if extension in {".html", ".htm"} or magic.startswith(("HTML document", "XHTML document")):
        return "html"
    if extension == ".js" or magic.startswith("JavaScript source"):
        return "javascript"
    if extension == ".css":
        return "css"
    if extension == ".svg" or magic.startswith("SVG"):
        return "svg"
    if extension in {".png", ".gif", ".ico"}:
        return extension[1:]
    return None


def _image_kind(extension: str, magic: str) -> Optional[str]:
    if magic.startswith("PNG image"):
        return "png"
    if magic.startswith("GIF image"):
        return "gif"
    if magic.startswith("JPEG image"):
        return "jpeg"
    if extension in {".png", ".gif", ".jpg", ".jpeg", ".ico"}:
        return extension[1:]
    return None


def _text_kind(extension: str, magic: str) -> Optional[str]:
    if "shell script" in magic:
        return "shell"
    if extension == ".lua":
        return "lua"
    if extension == ".uc":
        return "ucode"
    if extension == ".json" or magic.startswith("JSON text"):
        return "json"
    if extension in {".conf", ".config", ".nft", ".rules", ".txt", ".md5sum", ".pem", ".crt"}:
        return "config" if extension in {".conf", ".config", ".nft", ".rules"} else "text"
    if "text" in magic or magic == "empty":
        return "text"
    return None


def _text_summary(file: str) -> dict:
    summary = {"line_count": 0, "has_shebang": False}
    try:
        with open(file, "r", encoding="utf-8", errors="replace") as f:
            for index, line in enumerate(f, start=1):
                if index == 1:
                    summary["has_shebang"] = line.startswith("#!")
                summary["line_count"] = index
    except OSError as e:
        summary["read_error"] = str(e)
    return summary


def _opkg_control_fields(file: str, kind: str) -> dict:
    if kind != "control":
        return {}
    fields = {}
    try:
        with open(file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                fields[key.strip()] = value.strip()
    except OSError as e:
        return {"read_error": str(e)}
    return {"fields": fields}
