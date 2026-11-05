"""Timestamped terminal progress for experiment stages."""

import time


def report(message):
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)
