#!/usr/bin/env python3
"""Run the separate, synthetic-trust real-core-contract Linux packet profile."""
import importlib.util
from pathlib import Path


def main():
    path = Path(__file__).with_name('signed-linux-lab.py')
    spec = importlib.util.spec_from_file_location('isolated_signed_linux_runner', path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner.main(profile='core-access')


if __name__ == '__main__':
    raise SystemExit(main())
