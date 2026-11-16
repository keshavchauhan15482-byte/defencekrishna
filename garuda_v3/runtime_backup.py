"""Encrypted, tenant-bound SQLite snapshots; restore never reactivates policies.

Uses the SQLite online backup API, not a raw database/WAL file copy. Access tokens,
signing keys, packet uploads and model checkpoints are deliberately not backed up.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import struct
import tempfile
import time

MAGIC = b'KRISHNA-BACKUP-1\n'
MAX_DATABASE = 32 * 1024 * 1024
MAX_ARCHIVE = MAX_DATABASE + 65536


def read_key(path):
    if os.name != 'posix':
        raise ValueError('Private-key file checks currently require a POSIX host')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError('Backup key must be a private regular file (mode 0600)')
        if hasattr(os, 'getuid') and info.st_uid != os.getuid():
            raise ValueError('Backup key must belong to this service account')
        key = os.read(fd, 33)
        if len(key) != 32:
            raise ValueError('Backup key must contain exactly 32 random bytes')
        return key
    finally:
        os.close(fd)


def tenant_name(tenant):
    if not isinstance(tenant, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', tenant):
        raise ValueError('Explicit tenant identifier required (1..64 safe characters)')
    return tenant


def verify_database(db):
    if db.execute('PRAGMA quick_check').fetchone() != ('ok',):
        raise ValueError('SQLite integrity check failed')
    previous = '0' * 64
    count = 0
    for payload, prev, digest in db.execute('SELECT payload,previous_hash,hash FROM events ORDER BY id'):
        if not isinstance(payload, str) or prev != previous or hashlib.sha256((prev + payload).encode()).hexdigest() != digest:
            raise ValueError('Audit chain integrity check failed')
        previous = digest
        count += 1
    db.execute('SELECT id,target,expires,reason,status FROM policies LIMIT 1')
    return {'audit_head': previous, 'event_count': count}


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish_new(destination, content):
    """Atomic, no-overwrite publication; failure never exposes a partial archive."""
    destination = Path(destination)
    fd, name = tempfile.mkstemp(prefix='.krishna-backup-', dir=destination.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        # An exclusive hard link, unlike os.replace, cannot overwrite any target.
        os.link(name, destination)
        _sync_directory(destination.parent)
    finally:
        Path(name).unlink(missing_ok=True)


def backup_runtime(runtime, destination, key_file, tenant):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    tenant = tenant_name(tenant)
    key = read_key(key_file)
    runtime = Path(runtime).resolve(strict=True)
    destination = Path(destination).absolute()
    if destination.resolve().is_relative_to(runtime):
        raise ValueError('Store backups outside the live runtime directory')
    source = runtime / 'audit.sqlite'
    if source.is_symlink() or not source.is_file():
        raise ValueError('A regular existing audit database is required')
    started = time.monotonic()
    def progress(status, remaining, total):
        if total * page_size > MAX_DATABASE or time.monotonic() - started > 15:
            raise ValueError('Snapshot budget exceeded; use a reviewed large-database backup solution')
    with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True, timeout=2)) as origin:
        pages = origin.execute('PRAGMA page_count').fetchone()[0]
        page_size = origin.execute('PRAGMA page_size').fetchone()[0]
        if pages * page_size > MAX_DATABASE:
            raise ValueError('Pilot backup exceeds 32 MiB database limit')
        snapshot = sqlite3.connect(':memory:')
        try:
            origin.backup(snapshot, pages=128, progress=progress, sleep=.01)
            audit = verify_database(snapshot)
            database = snapshot.serialize()
            # Online backup has materialized WAL pages. SQLite documents that
            # deserialize requires rollback-format bytes 18/19, even in memory:
            # https://sqlite.org/c3ref/deserialize.html
            if not database.startswith(b'SQLite format 3\x00'):
                raise ValueError('Invalid SQLite snapshot header')
            database = database[:18] + b'\x01\x01' + database[20:]
        finally:
            snapshot.close()
    if len(database) > MAX_DATABASE:
        raise ValueError('Pilot backup exceeds 32 MiB database limit')
    manifest = dict(schema='krishna-encrypted-runtime-v1', tenant=tenant,
        created_unix=time.time(), database_sha256=hashlib.sha256(database).hexdigest(), **audit)
    metadata = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    plaintext = struct.pack('!I', len(metadata)) + metadata + database
    nonce = os.urandom(12)
    archive = MAGIC + nonce + AESGCM(key).encrypt(nonce, plaintext, MAGIC)
    _publish_new(destination, archive)
    return dict(status='encrypted_backup_created', bytes=len(archive), **manifest)


def restore_runtime(archive, destination, key_file, tenant):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    tenant = tenant_name(tenant)
    key = read_key(key_file)
    with Path(archive).open('rb') as stream:
        content = stream.read(MAX_ARCHIVE + 1)
    if len(content) > MAX_ARCHIVE or not content.startswith(MAGIC) or len(content) < len(MAGIC) + 28:
        raise ValueError('Invalid or oversized encrypted backup')
    offset = len(MAGIC)
    try:
        plaintext = AESGCM(key).decrypt(content[offset:offset+12], content[offset+12:], MAGIC)
    except InvalidTag as exc:
        raise ValueError('Backup authentication failed; wrong key or modified archive') from exc
    if len(plaintext) < 4:
        raise ValueError('Invalid backup metadata')
    length = struct.unpack('!I', plaintext[:4])[0]
    if not 0 < length <= 16384 or 4 + length >= len(plaintext):
        raise ValueError('Invalid backup metadata')
    manifest = json.loads(plaintext[4:4+length])
    database = plaintext[4+length:]
    if not isinstance(manifest, dict) or manifest.get('schema') != 'krishna-encrypted-runtime-v1' or manifest.get('tenant') != tenant:
        raise ValueError('Backup tenant/schema mismatch')
    if len(database) > MAX_DATABASE or hashlib.sha256(database).hexdigest() != manifest.get('database_sha256'):
        raise ValueError('Backup database hash mismatch')
    db = sqlite3.connect(':memory:')
    try:
        db.deserialize(database)
        audit = verify_database(db)
        if any(audit[k] != manifest.get(k) for k in audit):
            raise ValueError('Backup audit manifest mismatch')
        # Append a new audit event and revoke ALL historical active policies.
        # Never restore access.json, policy.json, tokens, signing keys or lab arming.
        db.execute('UPDATE policies SET status="revoked" WHERE status="active"')
        payload = json.dumps(dict(time=time.time(), action='offline_restore_shadow_only',
            details=dict(tenant=tenant, source_database_sha256=manifest['database_sha256'])),
            sort_keys=True, separators=(',', ':'))
        digest = hashlib.sha256((audit['audit_head'] + payload).encode()).hexdigest()
        db.execute('INSERT INTO events(payload,previous_hash,hash) VALUES(?,?,?)',
            (payload, audit['audit_head'], digest))
        db.commit()
        verify_database(db)
        destination = Path(destination).absolute()
        # mkdir is exclusive even if another process creates an empty target.
        destination.mkdir(mode=0o700, parents=False, exist_ok=False)
        marker = destination/'restore.incomplete'
        try:
            _publish_new(marker, b'Restore not completed; runtime startup must refuse.\n')
        except OSError:
            # Remove only the empty directory just created by this operation.
            # If publication succeeded but fsync failed, retain its failure marker.
            if not marker.exists():
                destination.rmdir()
            raise
        target = destination/'audit.sqlite'
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        restored = sqlite3.connect(target)
        try:
            db.backup(restored)
            verify_database(restored)
        finally:
            restored.close()
        fd = os.open(target, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        _sync_directory(destination)
        _sync_directory(destination.parent)
        marker.unlink()
        _sync_directory(destination)
        return dict(status='restored_shadow_only', tenant=tenant, policies_reactivated=0,
            credentials_restored=False, original_event_count=audit['event_count'])
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('backup', 'restore'))
    parser.add_argument('--runtime', required=True, help='Source runtime or NEW restore directory')
    parser.add_argument('--archive', required=True)
    parser.add_argument('--key-file', required=True, help='Private 32-byte key; never pass key bytes on command line')
    parser.add_argument('--tenant', required=True)
    args = parser.parse_args()
    try:
        result = backup_runtime(args.runtime, args.archive, args.key_file, args.tenant) if args.action == 'backup' else restore_runtime(args.archive, args.runtime, args.key_file, args.tenant)
    except ImportError:
        parser.exit(1, 'Install garuda_v3/requirements-pilot.txt before encrypted backup/restore.\n')
    except (ValueError, OSError, sqlite3.Error):
        parser.exit(1, 'Backup/restore failed; no success assumed. Check key, tenant, integrity, space and destination.\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
