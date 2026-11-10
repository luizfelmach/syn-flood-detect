#!/usr/bin/env python3
"""Plot server/firewall CPU and attacker SYN/s across attacker counts."""

from common.resource_series import main


if __name__ == "__main__":
    raise SystemExit(main("cpu"))
