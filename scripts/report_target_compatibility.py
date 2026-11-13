#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Compare create-only target reports with the unwind guard present/removed."""
import re
import subprocess
import sys

def collect(executable):
    result = subprocess.run([executable], capture_output=True, text=True, timeout=35)
    print(result.stdout, end='')
    print(result.stderr, end='', file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError('Target probe did not complete cleanly')
    rows = re.findall(r'^TARGET_PROBE name=(\w+) status=(MTH_\w+) enabled=0 executed=0$', result.stdout, re.M)
    if len(rows) != 11 or len(dict(rows)) != 11:
        raise RuntimeError('Expected eleven unique target classifications')
    return dict(rows)

def main():
    if len(sys.argv) != 3:
        raise RuntimeError('Expected production and guard-removal probe executables')
    production = collect(sys.argv[1])
    control = collect(sys.argv[2])
    if production.keys() != control.keys():
        raise RuntimeError('Probe target sets differ')
    narrowed = 0
    for name, status in production.items():
        if status == 'MTH_OK' and control[name] != 'MTH_OK':
            raise RuntimeError('Guard removal unexpectedly reduces compatibility: '+name)
        if status != control[name]:
            narrowed += 1
        print(f'TARGET_COMPARISON name={name} production={status} guard_removed={control[name]}')
    print(f'TARGET_COMPARISON_SUMMARY narrowed_by_unwind_guard={narrowed} integration_acceptance=NOT_ESTABLISHED')

if __name__ == '__main__':
    main()
