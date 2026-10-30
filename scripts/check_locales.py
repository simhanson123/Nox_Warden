#!/usr/bin/env python3
"""Check complete locale key/placeholder parity and safe rendering primitives."""
import json
import re
from pathlib import Path
root = Path(__file__).resolve().parents[1]
messages = json.loads((root / 'web/src/locales.json').read_text())
expected = {'en', 'ko', 'ja', 'es', 'zh-Hans', 'zh-Hant'}
assert set(messages) == expected, 'Missing locale'
keys = set(messages['en'])
# ICU branches may differ by plural rules; interpolation variable names must match.
def placeholders(value):
    return set(re.findall(r'\{(\w+)(?:\}|,\s*(?:plural|select|number|date|time))', value))
for locale, catalog in messages.items():
    assert set(catalog) == keys, f'{locale}: key mismatch'
    for key, value in catalog.items():
        assert isinstance(value, str) and value.strip(), f'{locale}/{key}: empty'
        assert placeholders(value) == placeholders(messages['en'][key]), f'{locale}/{key}: placeholder mismatch'
for path in (root / 'web/src').rglob('*.tsx'):
    assert 'dangerouslySetInnerHTML' not in path.read_text(), f'{path}: unsafe HTML rendering'
print(f'PASS: {len(expected)} locales, {len(keys)} keys, placeholder parity and escaped React rendering. Human language review remains unverified.')
