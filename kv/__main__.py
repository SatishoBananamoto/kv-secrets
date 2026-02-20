"""Entry point for python -m kv."""

import os
import sys

# Windows terminal setup
if os.name == "nt":
    os.system("")  # enable ANSI escape codes
    for stream in (sys.stdout, sys.stderr, sys.stdin):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

from .cli import main

if __name__ == "__main__":
    main()
