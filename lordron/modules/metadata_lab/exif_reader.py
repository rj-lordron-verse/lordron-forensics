"""
EXIF metadata extraction for images with GPS coordinate decoding.
Uses Pillow and optional ExifTool fallback. Never fabricates data.
"""

from __future__ import annotations
import shutil
import subprocess
import json
from pathlib import Path
from typing import Dict, Any
from lordron.core.paths import validate_file_path

try:
    from PIL import Image, ExifTags
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False


def _dms_to_decimal(degrees: float, minutes: float, seconds: float, reference: str) -> float:
    """Convert degrees, minutes, seconds to decimal degrees."""
    decimal = float(degrees) + (float(minutes) / 60.0) + (float(seconds) / 3600.0)
    if reference.upper() in ["S", "W"]:
        decimal = -decimal
    return round(decimal, 6)


def _parse_gps_info(gps_dict: Dict[int, Any]) -> Dict[str, Any]:
    """Parse GPS tags into human-readable coordinates and decimal degrees."""
    gps_data: Dict[str, Any] = {
        "status": "AVAILABLE",
        "raw_tags": {},
        "coordinates": None
    }

    gps_tags = {}
    for tag_id, value in gps_dict.items():
        tag_name = ExifTags.GPSTags.get(tag_id, str(tag_id))
        gps_tags[tag_name] = value

    gps_data["raw_tags"] = {k: str(v) for k, v in gps_tags.items()}

    # Extract Lat/Long if present
    lat_val = gps_tags.get("GPSLatitude")
    lat_ref = gps_tags.get("GPSLatitudeRef")
    lon_val = gps_tags.get("GPSLongitude")
    lon_ref = gps_tags.get("GPSLongitudeRef")

    if lat_val and lat_ref and lon_val and lon_ref:
        try:
            lat = _dms_to_decimal(lat_val[0], lat_val[1], lat_val[2], lat_ref)
            lon = _dms_to_decimal(lon_val[0], lon_val[1], lon_val[2], lon_ref)
            gps_data["coordinates"] = {
                "latitude_decimal": lat,
                "longitude_decimal": lon,
                "latitude_ref": str(lat_ref),
                "longitude_ref": str(lon_ref),
                "maps_url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"
            }
        except Exception:
            gps_data["coordinates"] = "UNABLE_TO_PARSE_DMS_VALUES"

    alt_val = gps_tags.get("GPSAltitude")
    if alt_val is not None:
        try:
            gps_data["altitude_meters"] = float(alt_val)
        except Exception:
            gps_data["altitude_meters"] = str(alt_val)

    return gps_data


def extract_image_metadata(file_path: str | Path, use_exiftool_if_available: bool = False) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from image files.
    Preserves original file. Distinguishes missing from empty metadata.
    """
    path = validate_file_path(file_path, must_exist=True)

    result: Dict[str, Any] = {
        "file_name": path.name,
        "format_category": "IMAGE",
        "has_exif": False,
        "dimensions": None,
        "color_mode": None,
        "camera": None,
        "timestamps": None,
        "gps": None,
        "all_exif_tags": {},
        "exiftool_output": None
    }

    if not PILLOW_AVAILABLE:
        result["error"] = "Pillow library is not installed."
        return result

    try:
        with Image.open(path) as img:
            result["dimensions"] = {"width": img.width, "height": img.height}
            result["color_mode"] = img.mode
            result["format"] = img.format

            exif_raw = img.getexif()
            if exif_raw:
                result["has_exif"] = True
                parsed_tags = {}
                camera_info = {}
                time_info = {}

                for tag_id, value in exif_raw.items():
                    tag_name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
                    # Convert bytes to string representation if needed
                    val_str = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
                    parsed_tags[tag_name] = val_str

                    if tag_name in ["Make", "Model", "Software", "LensModel"]:
                        camera_info[tag_name] = val_str
                    if tag_name in ["DateTime", "DateTimeOriginal", "DateTimeDigitized"]:
                        time_info[tag_name] = val_str

                result["all_exif_tags"] = parsed_tags
                result["camera"] = camera_info if camera_info else None
                result["timestamps"] = time_info if time_info else None

                # Check GPS IFD
                gps_ifd = exif_raw.get_ifd(ExifTags.IFD.GPSInfo) if hasattr(ExifTags, "IFD") else None
                if gps_ifd:
                    result["gps"] = _parse_gps_info(gps_ifd)
                else:
                    result["gps"] = {"status": "NOT_PRESENT"}
            else:
                result["has_exif"] = False
                result["gps"] = {"status": "NOT_PRESENT"}

    except Exception as exc:
        result["error"] = f"Unable to parse image metadata: {exc}"

    # Optional ExifTool integration
    if use_exiftool_if_available:
        exiftool_bin = shutil.which("exiftool")
        if exiftool_bin:
            try:
                proc = subprocess.run(
                    [exiftool_bin, "-j", str(path)],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=5,
                )
                if proc.returncode == 0:
                    data = json.loads(proc.stdout)
                    if data:
                        result["exiftool_output"] = data[0]
            except Exception:
                pass
        else:
            result["exiftool_output"] = None
            result["exiftool_note"] = "ExifTool was requested but binary was not found in PATH."

    return result
