"""
JSON report generator for LORDRON Forensics.
Produces clean, structured, machine-readable investigation outputs.
"""

from __future__ import annotations
import json
from typing import Dict, Any


def generate_json_report(report_data: Dict[str, Any]) -> str:
    """Format full case investigation data as an indented JSON string."""
    return json.dumps(report_data, indent=2, default=str)
