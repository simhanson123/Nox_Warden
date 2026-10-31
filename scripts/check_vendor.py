#!/usr/bin/env python3
"""Check the recorded upstream files and the narrow WebAuthn source patch.

This offline integrity check complements source review. It does not certify a
modified dependency or replace advisory review of its upstream release.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / 'vendor'
EXPECTED = {'webauthn-rs': '0.5.4', 'webauthn-rs-core': '0.5.4'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    require(path.is_file() and not path.is_symlink(), 'expected a regular source file')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative_path(value):
    path = PurePosixPath(value)
    require(not path.is_absolute() and '..' not in path.parts and str(path) == value,
            'noncanonical vendored path')
    return value


def verify_archives(crates, archive_dir, patch):
    require(archive_dir.is_dir(), 'archive directory does not exist')
    reconstructed_patch = []
    for entry in crates:
        name = f"{entry['name']}-{entry['version']}"
        archives = sorted(archive_dir.rglob(name + '.crate'))
        require(bool(archives), f'missing published archive: {name}')
        archive = archives[0]
        require(digest(archive) == entry['archive_sha256'],
                f'published archive hash differs: {name}')
        published = {}
        with tarfile.open(archive) as source:
            for member in source.getmembers():
                path = PurePosixPath(relative_path(member.name))
                require(member.isfile() and len(path.parts) > 1 and path.parts[0] == name,
                        'unexpected published archive member')
                relative = PurePosixPath(*path.parts[1:]).as_posix()
                require(relative not in published, 'duplicate published archive member')
                stream = source.extractfile(member)
                require(stream is not None, 'unreadable published archive member')
                original = stream.read()
                published[relative] = hashlib.sha256(original).hexdigest()
                current = (VENDOR / name / relative).read_bytes()
                if original != current:
                    reconstructed_patch.extend(difflib.unified_diff(
                        original.decode().splitlines(True), current.decode().splitlines(True),
                        fromfile='a/' + path.as_posix(), tofile='b/' + path.as_posix(),
                    ))
        require(published == entry['published_files'], 'published archive inventory differs')
    require(''.join(reconstructed_patch).encode() == patch.read_bytes(),
            'recorded patch differs from the published archive delta')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-dir', type=Path,
                        help='also verify published .crate archives in this directory tree')
    args = parser.parse_args()
    provenance = json.loads((VENDOR / 'webauthn-challenge-provenance.json').read_text())
    require(provenance['schema_version'] == 'fw.vendored-source-provenance/v1',
            'unknown provenance schema')
    crates = provenance['crates']
    require(len(crates) == len(EXPECTED) and
            {entry['name']: entry['version'] for entry in crates} == EXPECTED,
            'unexpected vendored package set')
    patch = VENDOR / relative_path(provenance['patch']['path'])
    require(digest(patch) == provenance['patch']['sha256'], 'patch hash differs')
    require(provenance['patch']['apply_from'] == 'vendor' and
            provenance['patch']['strip_components'] == 1, 'unexpected patch root')
    expected_changes = set()
    total_files = 0
    for entry in crates:
        name = f"{entry['name']}-{entry['version']}"
        directory = VENDOR / name
        require(directory.is_dir() and not directory.is_symlink(), 'missing vendored directory')
        original = {relative_path(p): h for p, h in entry['published_files'].items()}
        modified = {relative_path(f['path']): f['sha256'] for f in entry['modified_files']}
        require(len(modified) == len(entry['modified_files']) and
                modified.keys() <= original.keys(), 'invalid modified-file set')
        expected_changes.update(f'{name}/{p}' for p in modified)
        expected = original | modified | {'LICENSE.md': provenance['license_copy']['sha256']}
        actual = set()
        for path in directory.rglob('*'):
            require(not path.is_symlink(), 'vendored symlink is not allowed')
            if path.is_file():
                actual.add(path.relative_to(directory).as_posix())
        require(actual == expected.keys(), 'vendored file inventory differs')
        for path, checksum in expected.items():
            require(digest(directory / path) == checksum, f'vendored file changed: {name}/{path}')
        vcs = json.loads((directory / '.cargo_vcs_info.json').read_text())
        require(vcs['git']['sha1'] == provenance['upstream_git_revision'],
                'recorded upstream Git revision differs')
        total_files += len(expected)
    headers = {'--- a/': [], '+++ b/': []}
    for line in patch.read_text().splitlines():
        for prefix, paths in headers.items():
            if line.startswith(prefix):
                paths.append(relative_path(line[len(prefix):]))
    for paths in headers.values():
        require(len(paths) == len(expected_changes) and set(paths) == expected_changes,
                'patch does not match the reviewed modified-file set')

    # Reversing only the recorded diff must reproduce every published byte.
    # All writes occur in this temporary copy; no network or source tree edits.
    with tempfile.TemporaryDirectory(prefix='fw-vendor-check-') as temporary:
        temporary = Path(temporary)
        for entry in crates:
            name = f"{entry['name']}-{entry['version']}"
            shutil.copytree(VENDOR / name, temporary / name)
        result = subprocess.run(
            ['git', 'apply', '--reverse', '--whitespace=nowarn', '-p1', str(patch)],
            cwd=temporary, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        require(result.returncode == 0, 'recorded patch cannot be reversed cleanly')
        for entry in crates:
            directory = temporary / f"{entry['name']}-{entry['version']}"
            for path, checksum in entry['published_files'].items():
                require(digest(directory / path) == checksum,
                        'reversed source differs from recorded upstream bytes')
    if args.archive_dir is not None:
        verify_archives(crates, args.archive_dir, patch)
    print(f'PASS: {len(crates)} vendored packages, {total_files} files, '
          f'{len(expected_changes)} narrowly patched files; upstream-byte reconstruction verified.'
          + (' Published archive hashes and exact patch delta verified.'
             if args.archive_dir is not None else ''))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, tarfile.TarError) as error:
        raise SystemExit(f'Vendor integrity check failed: {error}') from None
