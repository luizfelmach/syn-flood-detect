#!/usr/bin/env python3
"""Plot server/firewall CPU with PACKET_HANDLING_MODE=allow."""

from common.resource_series import main


if __name__ == "__main__":
    raise SystemExit(main("cpu", mode="allow"))
