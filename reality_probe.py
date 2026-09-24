#!/usr/bin/env python3
"""
Reality Probe v4 — точка входа (совместимость с `python reality_probe.py`).
Код живёт в пакете realityprobe/; см. README.
"""

import sys

if sys.version_info < (3, 9):
    sys.exit("Python 3.9+ required")

from realityprobe.__main__ import main

if __name__ == "__main__":
    main()
