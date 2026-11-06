"""Check index contents without printing matched secret values."""
import argparse
import fnmatch
import re
import subprocess
import sys
from pathlib import PurePosixPath


PATTERNS = {
    'GitHub token': re.compile(r'(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})'),
    'API key': re.compile(r'\bsk-[A-Za-z0-9_-]{20,}'),
    'AWS access key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'private key': re.compile(r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----'),
    'personal Windows path': re.compile(r'(?i)\b[A-Z]:[\\/]Users[\\/](?!Public[\\/]|Default[\\/]|your-user[\\/])[^\s\'"<>]+'),
}
BLOCKED_DIRECTORIES = {'vaultdata', '.venv', 'build', 'dist', 'release', 'plugin-data', '__pycache__'}
BLOCKED_NAMES = ['.env', '.env.*', '*.key', '*.pem', '*.p12', '*.pfx', '*.log', 'database.sqlite*',
                 'settings.json', '*.jpv.zip', '*.jpv.enc', '*.rollback', '*.partial',
                 'plugin-vault-recovery*.json', '*.tmp-*']


def inspect(name, content):
    path = PurePosixPath(name.lower())
    if (any(part in BLOCKED_DIRECTORIES or part.startswith(('.jpv-swap-', 'jpv-backup-', 'jpv-verify-', 'jpv-preview-', 'jpv-restore-'))
            for part in path.parts[:-1])
            or (path.name != '.env.example' and any(fnmatch.fnmatchcase(path.name, pattern) for pattern in BLOCKED_NAMES))):
        return ['runtime data or credential file']
    text = content.decode('utf-8', errors='replace')
    return [label for label, pattern in PATTERNS.items() if pattern.search(text)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--all', action='store_true', help='Check every file in the Git index')
    args = parser.parse_args()
    command = ['git', 'ls-files', '-z'] if args.all else ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z']
    names = [name for name in subprocess.check_output(command).decode('utf-8').split('\0') if name]
    failed = False
    for name in names:
        content = subprocess.check_output(['git', 'show', ':' + name])
        for label in inspect(name, content):
            print(f'Blocked: {name}: {label}')
            failed = True
    if failed:
        print('Remove sensitive data from the index before committing. Matched values were not printed.')
    else:
        print(f'Secret check passed: {len(names)} indexed files.')
    return int(failed)


if __name__ == '__main__':
    sys.exit(main())
