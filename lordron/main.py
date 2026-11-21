"""
Main entry point for the LORDRON Forensics CLI application.
"""

from __future__ import annotations
import sys
from lordron.cli.commands import app
from lordron.core.exceptions import LordronError
from lordron.core.console import print_error


def main() -> None:
    """Execute the Lordron Forensics CLI application."""
    try:
        app()
    except LordronError as err:
        print_error(f"Lordron operational failure: {err}")
        sys.exit(1)
    except KeyboardInterrupt:
        print_error("Operation interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        print_error(f"Unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
