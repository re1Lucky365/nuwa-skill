[Unit]
Description=Master-Hub Data Pipeline Ingestion and Backup
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=%h/Master-Hub
Environment=ENCRYPT_BACKUP=1
ExecStart=/bin/bash -c 'set -euo pipefail; if [ -f data/incoming.jsonl ]; then python3 scripts/pipeline_ingest.py --input data/incoming.jsonl; fi; python3 scripts/hash_manifest.py generate --root . --output MANIFEST.sha256; bash scripts/backup_all.sh . "$HOME/backups"'
[Unit]
Description=Master-Hub Data Pipeline Ingestion and Backup
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=%h/Master-Hub
Environment=ENCRYPT_BACKUP=1
ExecStart=/bin/bash -c 'set -euo pipefail; if [ -f data/incoming.jsonl ]; then python3 scripts/pipeline_ingest.py --input data/incoming.jsonl; fi; python3 scripts/hash_manifest.py generate --root . --output MANIFEST.sha256; bash scripts/backup_all.sh . "$HOME/backups"'
#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HISTOGRAM_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


def canonical_record_hash(record: dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_records(input_path: Path) -> list[dict[str, Any]]:
    suffix = input_path.suffix.lower()
    if suffix == ".csv":
        with input_path.open("r", encoding="utf-8", newline="") as f:
            return [dict(row) for row in csv.DictReader(f)]
    if suffix in {".jsonl", ".ndjson"}:
        records: list[dict[str, Any]] = []
        for line in input_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records
    raise ValueError(f"Unsupported input format: {input_path.suffix}")


def to_ocsf_event(
    item: dict[str, Any],
    batch_id: str,
    ingested_at: str,
    epoch_ms: int,
    rec_hash: str,
) -> dict[str, Any]:
    severity_raw = str(item.get("severity", item.get("status", "info"))).lower()
    if severity_raw in {"crit", "critical", "error", "err", "fail", "failed"}:
        severity_id, severity = 4, "High"
    elif severity_raw in {"warn", "warning"}:
        severity_id, severity = 2, "Low"
    else:
        severity_id, severity = 1, "Informational"

    return {
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "severity_id": severity_id,
        "severity": severity,
        "time": epoch_ms,
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Master-Hub", "vendor_name": "Local-First"},
            "batch_id": batch_id,
            "ingested_at": ingested_at,
            "record_hash": rec_hash,
        },
        "observables": [{"name": "record_hash", "type_id": 10, "value": rec_hash}],
        "data": item,
    }


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pipeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            record_hash TEXT NOT NULL UNIQUE,
            ocsf_class_uid INTEGER NOT NULL,
            severity_id INTEGER NOT NULL,
            payload_json TEXT NOT NULL
        );
        """
    )
    conn.commit()
    return conn


def format_openmetrics(
    inserted: int,
    duplicates: int,
    duration_sec: float,
) -> str:
    lines = [
        "# HELP master_pipeline_records_total Total records processed in batch",
        "# TYPE master_pipeline_records_total counter",
        f'master_pipeline_records_total{{status="inserted"}} {inserted}',
        f'master_pipeline_records_total{{status="duplicate"}} {duplicates}',
        "# HELP master_pipeline_batch_duration_seconds Batch processing duration in seconds",
        "# TYPE master_pipeline_batch_duration_seconds histogram",
    ]
    for bound in HISTOGRAM_BUCKETS:
        count = 1 if duration_sec <= bound else 0
        lines.append(
            f'master_pipeline_batch_duration_seconds_bucket{{le="{bound}"}} {count}'
        )
    lines.append(f'master_pipeline_batch_duration_seconds_bucket{{le="+Inf"}} 1')
    lines.append(f"master_pipeline_batch_duration_seconds_sum {duration_sec:.6f}")
    lines.append("master_pipeline_batch_duration_seconds_count 1")
    lines.append("# EOF")
    return "\n".join(lines) + "\n"


def run_pipeline(
    input_path: Path,
    db_path: Path,
    jsonl_out: Path,
    metrics_out: Path,
) -> dict[str, Any]:
    start = time.perf_counter()
    now_dt = datetime.now(timezone.utc)
    batch_id = now_dt.strftime("%Y%m%dT%H%M%SZ")
    ingested_at = now_dt.isoformat()
    epoch_ms = int(now_dt.timestamp() * 1000)

    raw_records = load_records(input_path)
    conn = init_db(db_path)

    inserted = 0
    duplicates = 0
    normalized_lines: list[str] = []

    try:
        with conn:
            for item in raw_records:
                rec_hash = canonical_record_hash(item)
                event = to_ocsf_event(item, batch_id, ingested_at, epoch_ms, rec_hash)
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO pipeline_events
                        (batch_id, ingested_at, record_hash, ocsf_class_uid, severity_id, payload_json)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        batch_id,
                        ingested_at,
                        rec_hash,
                        event["class_uid"],
                        event["severity_id"],
                        json.dumps(event, sort_keys=True),
                    ),
                )
                if cur.rowcount == 1:
                    inserted += 1
                    normalized_lines.append(json.dumps(event, sort_keys=True))
                else:
                    duplicates += 1
    finally:
        conn.close()

    jsonl_out.parent.mkdir(parents=True, exist_ok=True)
    jsonl_out.write_text(
        "\n".join(normalized_lines) + ("\n" if normalized_lines else ""),
        encoding="utf-8",
    )

    elapsed = time.perf_counter() - start
    metrics_out.parent.mkdir(parents=True, exist_ok=True)
    metrics_out.write_text(
        format_openmetrics(inserted, duplicates, elapsed),
        encoding="utf-8",
    )

    return {
        "total_input": len(raw_records),
        "inserted": inserted,
        "duplicates": duplicates,
        "duration_seconds": round(elapsed, 6),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="OCSF-normalized local data pipeline ingester")
    parser.add_argument("--input", type=Path, required=True, help="Input .csv or .jsonl file")
    parser.add_argument("--db", type=Path, default=Path("data/pipeline.sqlite"))
    parser.add_argument("--jsonl-out", type=Path, default=Path("data/normalized.jsonl"))
    parser.add_argument("--metrics-out", type=Path, default=Path("data/metrics.prom"))
    args = parser.parse_args()

    stats = run_pipeline(args.input, args.db, args.jsonl_out, args.metrics_out)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
[Unit]
Description=Master-Hub Data Pipeline Ingestion and Backup
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=%h/Master-Hub
Environment=ENCRYPT_BACKUP=1
ExecStart=/bin/bash -c 'set -euo pipefail; if [ -f data/incoming.jsonl ]; then python3 scripts/pipeline_ingest.py --input data/incoming.jsonl; fi; python3 scripts/hash_manifest.py generate --root . --output MANIFEST.sha256; bash scripts/backup_all.sh . "$HOME/backups"'
name: Master Pipeline CI

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  pipeline-and-security:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Gitleaks secret scan
        uses: gitleaks/gitleaks-action@v2

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies & run pytest
        run: |
          python -m pip install --upgrade pip pytest cryptography
          PYTHONPATH=. pytest -v

      - name: Set up Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Build & test integrity-cli
        working-directory: crates/integrity-cli
        run: cargo test --locked || cargo test
from pathlib import Path

from scripts.hash_manifest import generate, verify
from scripts.pipeline_ingest import run_pipeline
from scripts.vault_encrypt import decrypt_file, encrypt_file


def test_pipeline_dedup_and_outputs(tmp_path: Path) -> None:
    csv_file = tmp_path / "events.csv"
    csv_file.write_text("event_id,status\n1,ok\n1,ok\n2,warn\n", encoding="utf-8")

    db_file = tmp_path / "pipeline.sqlite"
    jsonl_file = tmp_path / "out.jsonl"
    metrics_file = tmp_path / "metrics.prom"

    stats = run_pipeline(csv_file, db_file, jsonl_file, metrics_file)
    assert stats["total_input"] == 3
    assert stats["inserted"] == 2
    assert stats["duplicates"] == 1
    assert db_file.exists()
    assert jsonl_file.exists()
    assert "master_pipeline_records_total" in metrics_file.read_text(encoding="utf-8")


def test_manifest_and_vault_roundtrip(tmp_path: Path) -> None:
    sample = tmp_path / "payload.txt"
    sample.write_text("pipeline-state\n", encoding="utf-8")
    manifest = tmp_path / "MANIFEST.sha256"

    generate(tmp_path, manifest)
    assert verify(tmp_path, manifest) == 0

    enc = tmp_path / "payload.enc"
    dec = tmp_path / "restored.txt"
    encrypt_file(sample, enc, "test-passphrase")
    decrypt_file(enc, dec, "test-passphrase")
    assert dec.read_text(encoding="utf-8") == "pipeline-state\n"
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn hash_file(path: &Path) -> Result<String, std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn scan_dir(root: &Path) -> Result<BTreeMap<String, String>, std::io::Error> {
    let mut map = BTreeMap::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let path: PathBuf = entry.path().to_path_buf();
            if path.components().any(|c| {
                let s = c.as_os_str();
                s == ".git" || s == "target" || s == "__pycache__" || s == "data"
            }) {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            map.insert(rel, hash_file(&path)?);
        }
    }
    Ok(map)
}

fn main() {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "scan".to_string());
    let root = PathBuf::from(args.next().unwrap_or_else(|| ".".to_string()));

    match cmd.as_str() {
        "scan" => {
            let entries = scan_dir(&root).expect("failed scanning directory");
            for (rel, digest) in entries {
                println!("{digest}  {rel}");
            }
        }
        "check" => {
            let manifest_path =
                PathBuf::from(args.next().unwrap_or_else(|| "MANIFEST.sha256".to_string()));
            let content = fs::read_to_string(&manifest_path).expect("failed reading manifest");
            let current = scan_dir(&root).expect("failed scanning directory");
            let mut mismatches = 0;
            for line in content.lines() {
                if let Some((expected, rel)) = line.split_once("  ") {
                    match current.get(rel) {
                        Some(actual) if actual == expected => {}
                        _ => {
                            eprintln!("DRIFT: {rel}");
                            mismatches += 1;
                        }
                    }
                }
            }
            if mismatches > 0 {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("Usage: integrity-cli <scan|check> <dir> [manifest_path]");
            std::process::exit(2);
        }
    }
}
[package]
name = "integrity-cli"
version = "0.1.0"
edition = "2021"

[dependencies]
sha2 = "0.10"
walkdir = "2.5"
encrypt.py#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="${1:-.}"
BACKUP_ROOT="${2:-$HOME/backups}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STAGE_DIR="$(mktemp -d)"
ARCHIVE_BASENAME="backup_${TIMESTAMP}"
TAR_FILE="${STAGE_DIR}/${ARCHIVE_BASENAME}.tar"
ZST_FILE="${BACKUP_ROOT}/${ARCHIVE_BASENAME}.tar.zst"
MANIFEST_FILE="${BACKUP_ROOT}/${ARCHIVE_BASENAME}.sha256"

cleanup() {
  rm -rf "${STAGE_DIR}"
}
trap cleanup EXIT

mkdir -p "${BACKUP_ROOT}"

tar \
  --exclude='.git' \
  --exclude='target' \
  --exclude='__pycache__' \
  --exclude='node_modules' \
  --exclude='.venv' \
  --exclude='*.enc' \
  -cf "${TAR_FILE}" \
  -C "${SOURCE_DIR}" .

zstd -19 -T0 --rm "${TAR_FILE}" -o "${ZST_FILE}"
sha256sum "${ZST_FILE}" > "${MANIFEST_FILE}"

if [[ "${ENCRYPT_BACKUP:-0}" == "1" ]] && [[ -f "scripts/vault_encrypt.py" ]]; then
  python3 scripts/vault_encrypt.py encrypt "${ZST_FILE}" "${ZST_FILE}.enc"
  sha256sum "${ZST_FILE}.enc" >> "${MANIFEST_FILE}"
  rm -f "${ZST_FILE}"
  echo "Encrypted backup created: ${ZST_FILE}.enc"
else
  echo "Backup created: ${ZST_FILE}"
fi

echo "Manifest created: ${MANIFEST_FILE}"
#!/usr/bin/env python3
import argparse
import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
ITERATIONS = 480_000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_file(src: Path, dst: Path, password: str) -> None:
    salt = os.urandom(SALT_SIZE)
    token = Fernet(derive_key(password, salt)).encrypt(src.read_bytes())
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(salt + token)


def decrypt_file(src: Path, dst: Path, password: str) -> None:
    raw = src.read_bytes()
    salt, token = raw[:SALT_SIZE], raw[SALT_SIZE:]
    plain = Fernet(derive_key(password, salt)).decrypt(token)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(plain)


def main() -> None:
    parser = argparse.ArgumentParser(description="Symmetric file encryption/decryption")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc_p = sub.add_parser("encrypt")
    enc_p.add_argument("src", type=Path)
    enc_p.add_argument("dst", type=Path)

    dec_p = sub.add_parser("decrypt")
    dec_p.add_argument("src", type=Path)
    dec_p.add_argument("dst", type=Path)

    args = parser.parse_args()
    password = os.environ.get("VAULT_PASSPHRASE") or input("Enter vault passphrase: ")
    if args.cmd == "encrypt":
        encrypt_file(args.src, args.dst, password)
    else:
        decrypt_file(args.src, args.dst, password)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import argparse
import hashlib
from pathlib import Path

EXCLUDE_DIRS = {".git", "__pycache__", "target", ".pytest_cache", "backups", "vault", "data"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def generate(root: Path, output: Path) -> None:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_dir() or any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        if path.resolve() == output.resolve():
            continue
        rel = path.relative_to(root).as_posix()
        lines.append(f"{sha256_file(path)}  {rel}")
    output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def verify(root: Path, manifest: Path) -> int:
    mismatches = 0
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split("  ", 1)
        target = root / rel
        if not target.exists() or sha256_file(target) != expected:
            print(f"MISMATCH: {rel}")
            mismatches += 1
    return mismatches


def main() -> None:
    parser = argparse.ArgumentParser(description="SHA-256 manifest generator and verifier")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen_p = sub.add_parser("generate")
    gen_p.add_argument("--root", type=Path, default=Path("."))
    gen_p.add_argument("--output", type=Path, default=Path("MANIFEST.sha256"))

    ver_p = sub.add_parser("verify")
    ver_p.add_argument("--root", type=Path, default=Path("."))
    ver_p.add_argument("--manifest", type=Path, default=Path("MANIFEST.sha256"))

    args = parser.parse_args()
    if args.cmd == "generate":
        generate(args.root, args.output)
    else:
        bad = verify(args.root, args.manifest)
        raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
path.is#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def canonical_record_hash(record: dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_records(input_path: Path) -> list[dict[str, Any]]:
    suffix = input_path.suffix.lower()
    if suffix == ".csv":
        with input_path.open("r", encoding="utf-8", newline="") as f:
            return [dict(row) for row in csv.DictReader(f)]
    if suffix in {".jsonl", ".ndjson"}:
        records: list[dict[str, Any]] = []
        for line in input_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records
    raise ValueError(f"Unsupported input format: {input_path.suffix}")


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pipeline_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            record_hash TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL
        );
        """
    )
    conn.commit()
    return conn


def run_pipeline(
    input_path: Path,
    db_path: Path,
    jsonl_out: Path,
    metrics_out: Path,
) -> dict[str, int]:
    batch_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ingested_at = datetime.now(timezone.utc).isoformat()
    raw_records = load_records(input_path)
    conn = init_db(db_path)

    inserted = 0
    duplicates = 0
    normalized_lines: list[str] = []

    try:
        with conn:
            for item in raw_records:
                rec_hash = canonical_record_hash(item)
                envelope = {
                    "batch_id": batch_id,
                    "ingested_at": ingested_at,
                    "record_hash": rec_hash,
                    "data": item,
                }
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO pipeline_events
                        (batch_id, ingested_at, record_hash, payload_json)
                    VALUES (?, ?, ?, ?);
                    """,
                    (batch_id, ingested_at, rec_hash, json.dumps(envelope, sort_keys=True)),
                )
                if cur.rowcount == 1:
                    inserted += 1
                    normalized_lines.append(json.dumps(envelope, sort_keys=True))
                else:
                    duplicates += 1
    finally:
        conn.close()

    jsonl_out.parent.mkdir(parents=True, exist_ok=True)
    jsonl_out.write_text(
        "\n".join(normalized_lines) + ("\n" if normalized_lines else ""),
        encoding="utf-8",
    )

    metrics_out.parent.mkdir(parents=True, exist_ok=True)
    metrics_text = (
        "# HELP master_pipeline_records_total Total records processed in batch\n"
        "# TYPE master_pipeline_records_total counter\n"
        f'master_pipeline_records_total{{status="inserted"}} {inserted}\n'
        f'master_pipeline_records_total{{status="duplicate"}} {duplicates}\n'
        "# EOF\n"
    )
    metrics_out.write_text(metrics_text, encoding="utf-8")

    return {
        "total_input": len(raw_records),
        "inserted": inserted,
        "duplicates": duplicates,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic local data pipeline ingester")
    parser.add_argument("--input", type=Path, required=True, help="Input .csv or .jsonl file")
    parser.add_argument("--db", type=Path, default=Path("data/pipeline.sqlite"))
    parser.add_argument("--jsonl-out", type=Path, default=Path("data/normalized.jsonl"))
    parser.add_argument("--metrics-out", type=Path, default=Path("data/metrics.prom"))
    args = parser.parse_args()

    stats = run_pipeline(args.input, args.db, args.jsonl_out, args.metrics_out)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
Master-Hub/
├── .github/
│   └── workflows/
│       └── master-pipeline-ci.yml
├── .gitleaks.toml
├── .gitignore
├── README.md
├── scripts/
│   ├── bootstrap.sh
│   ├── audit_gpg.sh
│   ├── hash_manifest.py
│   ├── vault_encrypt.py
│   ├── backup_all.sh
│   └── pipeline_ingest.py
├── crates/
│   └── integrity-cli/
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
└── tests/
    └── test_pipeline_and_tools.py
README.md
Robert Edward Evans 
evansrobert517@gmail.com 
evansrobert517@yahoo.com 
adpsnake812@gmail.com 
adpsnake7@gmail.com 
To make your local repositories, automation pipelines, and AI workflows cleaner, safer, transparent, and aligned with good operational and compliance hygiene, add explicit secret/PII hygiene checks, honest data/AI provenance metadata, and fail-closed audit logging—while keeping all enforcement strictly local to files you authorize. (This is general software engineering guidance, not legal advice.)
1. Clean Pipeline & Provenance Guard (scripts/clean_pipeline_guard.py)
This script builds on your local audit workflow to:
 * Scan non-ignored text/config files for accidental private keys, tokens, or SSN-like patterns before committing or bundling.
 * Require and verify a clean provenance.json manifest (declaring whether data is synthetic/sanitized, local-only, and non-clinical/non-legal-advice) alongside SHA256SUMS.
 * Output a clear, honest JSON report with deterministic exit codes (0 when clean, 1 when issues are found).
#!/usr/bin/env python3
"""Run local hygiene, provenance transparency, and SHA-256 integrity checks."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv"}

SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key_block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_classic_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_fine_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("ssn_like_pattern", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]

REQUIRED_PROVENANCE_KEYS = {
    "service_name",
    "data_classification",
    "local_only_processing",
    "automated_external_actions",
    "disclaimer",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_for_secrets(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            for label, pattern in SENSITIVE_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        {
                            "file": str(path.relative_to(root)),
                            "line": line_no,
                            "rule": label,
                        }
                    )
    return findings


def check_provenance(provenance_path: Path | None) -> dict[str, Any]:
    if provenance_path is None:
        return {"checked": False, "ok": True, "errors": []}
    if not provenance_path.is_file():
        return {"checked": True, "ok": False, "errors": [f"Missing provenance file: {provenance_path}"]}
    try:
        data = json.loads(provenance_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"checked": True, "ok": False, "errors": [f"Invalid provenance JSON: {exc}"]}

    errors: list[str] = []
    if not isinstance(data, dict):
        return {"checked": True, "ok": False, "errors": ["Provenance root must be a JSON object"]}

    missing = sorted(REQUIRED_PROVENANCE_KEYS - set(data.keys()))
    if missing:
        errors.append(f"Missing required provenance fields: {', '.join(missing)}")

    if "local_only_processing" in data and not isinstance(data["local_only_processing"], bool):
        errors.append("Field 'local_only_processing' must be a boolean")

    if "automated_external_actions" in data and data["automated_external_actions"] is not False:
        errors.append("Field 'automated_external_actions' must be explicitly false for safe local runs")

    return {"checked": True, "ok": len(errors) == 0, "errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser(description="Clean, transparent local pipeline guard.")
    parser.add_argument("--root", type=Path, default=Path("."), help="Workspace root to audit")
    parser.add_argument("--provenance", type=Path, default=None, help="Optional provenance.json file")
    args = parser.parse_args()

    root = args.root.resolve()
    provenance_path = args.provenance.resolve() if args.provenance else None

    secret_findings = scan_for_secrets(root)
    provenance_report = check_provenance(provenance_path)

    passed = len(secret_findings) == 0 and provenance_report["ok"]
    summary = {
        "root": str(root),
        "passed": passed,
        "secret_or_pii_findings_count": len(secret_findings),
        "secret_or_pii_findings": secret_findings,
        "provenance": provenance_report,
    }
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

2. Core Principles for Clean, Honest, Lawful Pipelines
 * Explicit boundaries over hidden automation: Keep scripts local-first, read-only where possible, and explicit about any outbound actions (automated_external_actions: false unless intentionally invoked). Never embed active credentials, private keys, or real personal identifiers in code or sample fixtures.
 * Honest AI & telemetry reporting: Label synthetic test data and simulated states clearly, avoid fabricated metrics or overclaimed certainty, and log deterministic hashes (sha256sum) so results can be independently verified.
 * Fair & lawful access practices: Only audit systems, directories, and accounts you own or are explicitly authorized to manage, and respect platform terms, privacy controls, and applicable laws.
 * Professional release hygiene: Keep commits small and scoped, enforce signed commits/tags on protected branches, and run automated tests (pytest) before tagging releases.
provenance.json
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-.}"
MANIFEST_PATH="${2:-}"
PROVENANCE_PATH="${3:-}"
LOG_DIR="${PIPELINE_LOG_DIR:-${HOME}/.local/state/master_pipeline}"
TIMESTAMP_UTC="$(date -u +"%Y-%m-%dT%H-%M-%SZ")"
LOG_FILE="${LOG_DIR}/pipeline_runs.jsonl"

mkdir -p "${LOG_DIR}"

AUDIT_CMD=(python3 scripts/local_workspace_audit.py --root "${ROOT_DIR}")
if [[ -n "${MANIFEST_PATH}" ]]; then
  AUDIT_CMD+=(--manifest "${MANIFEST_PATH}")
fi

GUARD_CMD=(python3 scripts/clean_pipeline_guard.py --root "${ROOT_DIR}")
if [[ -n "${PROVENANCE_PATH}" ]]; then
  GUARD_CMD+=(--provenance "${PROVENANCE_PATH}")
fi

echo "[1/3] Running local workspace & manifest audit..."
"${AUDIT_CMD[@]}"

echo "[2/3] Running clean pipeline & provenance guard..."
"${GUARD_CMD[@]}"

echo "[3/3] Running pytest suite..."
pytest -q

printf '{"timestamp_utc":"%s","root":"%s","status":"PASSED"}\n' \
  "${TIMESTAMP_UTC}" \
  "$(cd "${ROOT_DIR}" && pwd)" >> "${LOG_FILE}"

echo "Master pipeline passed. Logged to ${LOG_FILE}"
chmod +x scripts/run_master_pipeline.sh
bash scripts/run_master_pipeline.sh . build/SHA256SUMS config/provenance.json
tail -n 5 "${HOME}/.local/state/master_pipeline/pipeline_runs.jsonl"
A practical "Master System & Pipeline" for a local-first engineering setup is a single, deterministic entry point that runs your validation checks, verifies SHA-256 integrity manifests, runs pytest, and records an auditable local log—without hidden network side effects or overclaimed automation. (This is general software engineering guidance, not legal or security advice.)
1. Unified Local Master Runner (scripts/run_master_pipeline.sh)
This shell script executes your workspace audit, clean pipeline/provenance guard, and pytest suite in order, writing a timestamped JSON-lines summary to a local log directory while failing closed (set -euo pipefail) if any check fails.
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-.}"
MANIFEST_PATH="${2:-}"
PROVENANCE_PATH="${3:-}"
LOG_DIR="${PIPELINE_LOG_DIR:-${HOME}/.local/state/master_pipeline}"
TIMESTAMP_UTC="$(date -u +"%Y-%m-%dT%H-%M-%SZ")"
LOG_FILE="${LOG_DIR}/pipeline_runs.jsonl"

mkdir -p "${LOG_DIR}"

AUDIT_CMD=(python3 scripts/local_workspace_audit.py --root "${ROOT_DIR}")
if [[ -n "${MANIFEST_PATH}" ]]; then
  AUDIT_CMD+=(--manifest "${MANIFEST_PATH}")
fi

GUARD_CMD=(python3 scripts/clean_pipeline_guard.py --root "${ROOT_DIR}")
if [[ -n "${PROVENANCE_PATH}" ]]; then
  GUARD_CMD+=(--provenance "${PROVENANCE_PATH}")
fi

echo "[1/3] Running local workspace & manifest audit..."
"${AUDIT_CMD[@]}"

echo "[2/3] Running clean pipeline & provenance guard..."
"${GUARD_CMD[@]}"

echo "[3/3] Running pytest suite..."
pytest -q

printf '{"timestamp_utc":"%s","root":"%s","status":"PASSED"}\n' \
  "${TIMESTAMP_UTC}" \
  "$(cd "${ROOT_DIR}" && pwd)" >> "${LOG_FILE}"

echo "Master pipeline passed. Logged to ${LOG_FILE}"

2. How to Run & Verify It
 * Make the script executable:
   chmod +x scripts/run_master_pipeline.sh

 * Run against your repository root (and optionally pass a SHA256SUMS manifest and provenance.json):
   bash scripts/run_master_pipeline.sh . build/SHA256SUMS config/provenance.json

 * Inspect the append-only run log:
   tail -n 5 "${HOME}/.local/state/master_pipeline/pipeline_runs.jsonl"

3. Guardrails for Multi-Stage & Cross-Repo Pipelines
 * Explicit over implicit: Pass paths, remotes, and flags explicitly rather than relying on silent background changes or unverified external endpoints.
 * Immutable, checksummed artifacts: Pair every archive or release bundle (such as tar.zst) with a sha256sum manifest and verify it before moving files to backup or mirror targets.
 * Honest boundaries: Keep sensitive records, credentials, and real personal data out of Git repositories, and treat any simulated or synthetic outputs strictly as test artifacts.
Here is how to add deterministic tar.zst archive packaging with matching .sha256 manifests and customizable workspace rules (--forbid-name, --require-path) so your pipeline covers both artifact bundling and stricter repository checks.
1. Packaging tar.zst Bundles with SHA-256 Checksums (scripts/package_bundle.py)
This script packages a target directory into a deterministic .tar.zst archive (sorting entries, normalizing timestamps/permissions, and setting mtime=0 for reproducibility) and writes a companion <archive>.sha256 file.
#!/usr/bin/env python3
"""Create a deterministic tar.zst archive and companion SHA-256 checksum file."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

EXCLUDED_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}


def _reset_tarinfo(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    if info.isdir():
        info.mode = 0o755
    elif info.isfile():
        info.mode = 0o644
    return info


def build_deterministic_tar(source_dir: Path, tar_path: Path) -> None:
    source_resolved = source_dir.resolve()
    files_and_dirs: list[tuple[Path, str]] = []

    for current_root, dirnames, filenames in os.walk(source_resolved):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
        filenames.sort()

        current_path = Path(current_root)
        rel_root = current_path.relative_to(source_resolved)

        if str(rel_root) != ".":
            files_and_dirs.append((current_path, rel_root.as_posix()))

        for fname in filenames:
            full_file = current_path / fname
            if full_file.is_symlink():
                continue
            arcname = fname if str(rel_root) == "." else f"{rel_root.as_posix()}/{fname}"
            files_and_dirs.append((full_file, arcname))

    with tarfile.open(tar_path, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for src_path, arcname in files_and_dirs:
            tf.add(src_path, arcname=arcname, recursive=False, filter=_reset_tarinfo)


def compress_zst(tar_path: Path, zst_path: Path, level: int = 3) -> None:
    zst_path.parent.mkdir(parents=True, exist_ok=True)
    with tar_path.open("rb") as src, zst_path.open("wb") as dst:
        subprocess.run(
            ["zstd", f"-{level}", "--force", "--stdout"],
            stdin=src,
            stdout=dst,
            check=True,
        )


def write_sha256_sidecar(artifact_path: Path, checksum_path: Path) -> str:
    h = hashlib.sha256()
    with artifact_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    digest = h.hexdigest()
    checksum_path.write_text(f"{digest}  {artifact_path.name}\n", encoding="utf-8")
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package deterministic tar.zst bundle + SHA-256.")
    parser.add_argument("--source", required=True, help="Directory to archive")
    parser.add_argument("--out", required=True, help="Output .tar.zst path")
    parser.add_argument("--level", type=int, default=3, help="zstd compression level (1-19)")
    args = parser.parse_args(argv)

    source_dir = Path(args.source)
    if not source_dir.is_dir():
        print(f"[BUNDLE FAIL] Source directory not found: {source_dir}", file=sys.stderr)
        return 1

    zst_path = Path(args.out)
    if not zst_path.name.endswith(".tar.zst"):
        print(f"[BUNDLE FAIL] Output path must end with .tar.zst: {zst_path}", file=sys.stderr)
        return 1

    checksum_path = Path(f"{zst_path}.sha256")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_tar = Path(tmpdir) / "bundle.tar"
            build_deterministic_tar(source_dir, raw_tar)
            compress_zst(raw_tar, zst_path, level=args.level)
        digest = write_sha256_sidecar(zst_path, checksum_path)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        print(f"[BUNDLE FAIL] {exc}", file=sys.stderr)
        return 1

    print(f"[BUNDLE OK] archive={zst_path} sha256={digest} sidecar={checksum_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

2. Custom Rules in scripts/local_workspace_audit.py
Update audit_workspace and main in scripts/local_workspace_audit.py so you can pass repeatable --require-path and --forbid-name flags from the CLI or wrapper script:
# Add these helper checks inside audit_workspace(root, manifest, required_paths=(), forbidden_names=()):
    root_resolved = root.resolve()

    for req_rel in required_paths:
        req_target = (root_resolved / req_rel).resolve()
        if not req_target.exists():
            errors.append(f"Missing required workspace path: {req_rel}")

    if forbidden_names:
        forbidden_set = set(forbidden_names)
        ignored_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}
        for path in root_resolved.rglob("*"):
            if any(part in ignored_dirs for part in path.parts):
                continue
            if path.name in forbidden_set:
                errors.append(f"Forbidden workspace item found: {path.relative_to(root_resolved)}")

And in main:
    parser.add_argument(
        "--require-path",
        action="append",
        default=[],
        help="Relative path that must exist under --root (repeatable)",
    )
    parser.add_argument(
        "--forbid-name",
        action="append",
        default=[],
        help="File or directory name forbidden under --root (repeatable)",
    )

3. Wiring Packaging & Verification Together
chmod +x scripts/package_bundle.py

# 1. Build a checksummed .tar.zst bundle into build/
python3 scripts/package_bundle.py --source . --out build/workspace_bundle.tar.zst

# 2. Verify the bundle's own SHA-256 sidecar from build/
(cd build && sha256sum -c workspace_bundle.tar.zst.sha256)

# 3. Run your master pipeline with custom workspace rules
python3 scripts/local_workspace_audit.py \
  --root . \
  --manifest build/SHA256SUMS \
  --require-path README.md \
  --forbid-name .DS_Store

Would you like to wire scripts/package_bundle.py directly into scripts/run_master_pipeline.sh behind an optional flag (like --bundle-out), or add tests for the new packaging and custom audit rules?
chmod +x scripts/package_bundle.py

# 1. Build a checksummed .tar.zst bundle into build/
python3 scripts/package_bundle.py --source . --out build/workspace_bundle.tar.zst

# 2. Verify the bundle's own SHA-256 sidecar from build/
(cd build && sha256sum -c workspace_bundle.tar.zst.sha256)

# 3. Run your master pipeline with custom workspace rules
python3 scripts/local_workspace_audit.py \
  --root . \
  --manifest build/SHA256SUMS \
  --require-path README.md \
  --forbid-name .DS_Store
    parser.add_argument(
        "--require-path",
        action="append",
        default=[],
        help="Relative path that must exist under --root (repeatable)",
    )
    parser.add_argument(
        "--forbid-name",
        action="append",
        default=[],
        help="File or directory name forbidden under --root (repeatable)",
    )
# Add these helper checks inside audit_workspace(root, manifest, required_paths=(), forbidden_names=()):
    root_resolved = root.resolve()

    for req_rel in required_paths:
        req_target = (root_resolved / req_rel).resolve()
        if not req_target.exists():
            errors.append(f"Missing required workspace path: {req_rel}")

    if forbidden_names:
        forbidden_set = set(forbidden_names)
        ignored_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}
        for path in root_resolved.rglob("*"):
            if any(part in ignored_dirs for part in path.parts):
                continue
            if path.name in forbidden_set:
                errors.append(f"Forbidden workspace item found: {path.relative_to(root_resolved)}")
#!/usr/bin/env python3
"""Create a deterministic tar.zst archive and companion SHA-256 checksum file."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

EXCLUDED_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}


def _reset_tarinfo(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    if info.isdir():
        info.mode = 0o755
    elif info.isfile():
        info.mode = 0o644
    return info


def build_deterministic_tar(source_dir: Path, tar_path: Path) -> None:
    source_resolved = source_dir.resolve()
    files_and_dirs: list[tuple[Path, str]] = []

    for current_root, dirnames, filenames in os.walk(source_resolved):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
        filenames.sort()

        current_path = Path(current_root)
        rel_root = current_path.relative_to(source_resolved)

        if str(rel_root) != ".":
            files_and_dirs.append((current_path, rel_root.as_posix()))

        for fname in filenames:
            full_file = current_path / fname
            if full_file.is_symlink():
                continue
            arcname = fname if str(rel_root) == "." else f"{rel_root.as_posix()}/{fname}"
            files_and_dirs.append((full_file, arcname))

    with tarfile.open(tar_path, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for src_path, arcname in files_and_dirs:
            tf.add(src_path, arcname=arcname, recursive=False, filter=_reset_tarinfo)


def compress_zst(tar_path: Path, zst_path: Path, level: int = 3) -> None:
    zst_path.parent.mkdir(parents=True, exist_ok=True)
    with tar_path.open("rb") as src, zst_path.open("wb") as dst:
        subprocess.run(
            ["zstd", f"-{level}", "--force", "--stdout"],
            stdin=src,
            stdout=dst,
            check=True,
        )


def write_sha256_sidecar(artifact_path: Path, checksum_path: Path) -> str:
    h = hashlib.sha256()
    with artifact_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    digest = h.hexdigest()
    checksum_path.write_text(f"{digest}  {artifact_path.name}\n", encoding="utf-8")
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package deterministic tar.zst bundle + SHA-256.")
    parser.add_argument("--source", required=True, help="Directory to archive")
    parser.add_argument("--out", required=True, help="Output .tar.zst path")
    parser.add_argument("--level", type=int, default=3, help="zstd compression level (1-19)")
    args = parser.parse_args(argv)

    source_dir = Path(args.source)
    if not source_dir.is_dir():
        print(f"[BUNDLE FAIL] Source directory not found: {source_dir}", file=sys.stderr)
        return 1

    zst_path = Path(args.out)
    if not zst_path.name.endswith(".tar.zst"):
        print(f"[BUNDLE FAIL] Output path must end with .tar.zst: {zst_path}", file=sys.stderr)
        return 1

    checksum_path = Path(f"{zst_path}.sha256")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_tar = Path(tmpdir) / "bundle.tar"
            build_deterministic_tar(source_dir, raw_tar)
            compress_zst(raw_tar, zst_path, level=args.level)
        digest = write_sha256_sidecar(zst_path, checksum_path)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        print(f"[BUNDLE FAIL] {exc}", file=sys.stderr)
        return 1

    print(f"[BUNDLE OK] archive={zst_path} sha256={digest} sidecar={checksum_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
chmod +x scripts/package_bundle.py

# 1. Build a checksummed .tar.zst bundle into build/
python3 scripts/package_bundle.py --source . --out build/workspace_bundle.tar.zst

# 2. Verify the bundle's own SHA-256 sidecar from build/
(cd build && sha256sum -c workspace_bundle.tar.zst.sha256)

# 3. Run your master pipeline with custom workspace rules
python3 scripts/local_workspace_audit.py \
  --root . \
  --manifest build/SHA256SUMS \
  --require-path README.md \
  --forbid-name .DS_Store
bundle.py
    parser.add_argument(
        "--require-path",
        action="append",
        default=[],
        help="Relative path that must exist under --root (repeatable)",
    )
    parser.add_argument(
        "--forbid-name",
        action="append",
        default=[],
        help="File or directory name forbidden under --root (repeatable)",
    )
# Add these helper checks inside audit_workspace(root, manifest, required_paths=(), forbidden_names=()):
    root_resolved = root.resolve()

    for req_rel in required_paths:
        req_target = (root_resolved / req_rel).resolve()
        if not req_target.exists():
            errors.append(f"Missing required workspace path: {req_rel}")

    if forbidden_names:
        forbidden_set = set(forbidden_names)
        ignored_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}
        for path in root_resolved.rglob("*"):
            if any(part in ignored_dirs for part in path.parts):
                continue
            if path.name in forbidden_set:
                errors.append(f"Forbidden workspace item found: {path.relative_to(root_resolved)}")
path.name
path.name
#!/usr/bin/env python3
"""Create a deterministic tar.zst archive and companion SHA-256 checksum file."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

EXCLUDED_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}


def _reset_tarinfo(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    if info.isdir():
        info.mode = 0o755
    elif info.isfile():
        info.mode = 0o644
    return info


def build_deterministic_tar(source_dir: Path, tar_path: Path) -> None:
    source_resolved = source_dir.resolve()
    files_and_dirs: list[tuple[Path, str]] = []

    for current_root, dirnames, filenames in os.walk(source_resolved):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
        filenames.sort()

        current_path = Path(current_root)
        rel_root = current_path.relative_to(source_resolved)

        if str(rel_root) != ".":
            files_and_dirs.append((current_path, rel_root.as_posix()))

        for fname in filenames:
            full_file = current_path / fname
            if full_file.is_symlink():
                continue
            arcname = fname if str(rel_root) == "." else f"{rel_root.as_posix()}/{fname}"
            files_and_dirs.append((full_file, arcname))

    with tarfile.open(tar_path, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for src_path, arcname in files_and_dirs:
            tf.add(src_path, arcname=arcname, recursive=False, filter=_reset_tarinfo)


def compress_zst(tar_path: Path, zst_path: Path, level: int = 3) -> None:
    zst_path.parent.mkdir(parents=True, exist_ok=True)
    with tar_path.open("rb") as src, zst_path.open("wb") as dst:
        subprocess.run(
            ["zstd", f"-{level}", "--force", "--stdout"],
            stdin=src,
            stdout=dst,
            check=True,
        )


def write_sha256_sidecar(artifact_path: Path, checksum_path: Path) -> str:
    h = hashlib.sha256()
    with artifact_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    digest = h.hexdigest()
    checksum_path.write_text(f"{digest}  {artifact_path.name}\n", encoding="utf-8")
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package deterministic tar.zst bundle + SHA-256.")
    parser.add_argument("--source", required=True, help="Directory to archive")
    parser.add_argument("--out", required=True, help="Output .tar.zst path")
    parser.add_argument("--level", type=int, default=3, help="zstd compression level (1-19)")
    args = parser.parse_args(argv)

    source_dir = Path(args.source)
    if not source_dir.is_dir():
        print(f"[BUNDLE FAIL] Source directory not found: {source_dir}", file=sys.stderr)
        return 1

    zst_path = Path(args.out)
    if not zst_path.name.endswith(".tar.zst"):
        print(f"[BUNDLE FAIL] Output path must end with .tar.zst: {zst_path}", file=sys.stderr)
        return 1

    checksum_path = Path(f"{zst_path}.sha256")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_tar = Path(tmpdir) / "bundle.tar"
            build_deterministic_tar(source_dir, raw_tar)
            compress_zst(raw_tar, zst_path, level=args.level)
        digest = write_sha256_sidecar(zst_path, checksum_path)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        print(f"[BUNDLE FAIL] {exc}", file=sys.stderr)
        return 1

    print(f"[BUNDLE OK] archive={zst_path} sha256={digest} sidecar={checksum_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="."
MANIFEST_PATH=""
PROVENANCE_PATH=""
BUNDLE_OUT=""
ZSTD_LEVEL="${ZSTD_LEVEL:-3}"
LOG_DIR="${PIPELINE_LOG_DIR:-${HOME}/.local/state/master_pipeline}"
LOG_FILE="${LOG_DIR}/pipeline_runs.jsonl"

REQUIRED_PATHS=()
FORBIDDEN_NAMES=()

# Allow positional arguments first for backward compatibility:
#   run_master_pipeline.sh [ROOT_DIR] [MANIFEST_PATH] [PROVENANCE_PATH] [--flag value ...]
if [[ $# -gt 0 && "${1}" != --* ]]; then
  ROOT_DIR="${1}"
  shift
fi
if [[ $# -gt 0 && "${1}" != --* ]]; then
  MANIFEST_PATH="${1}"
  shift
fi
if [[ $# -gt 0 && "${1}" != --* ]]; then
  PROVENANCE_PATH="${1}"
  shift
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      ROOT_DIR="${2:?--root requires a path}"
      shift 2
      ;;
    --manifest)
      MANIFEST_PATH="${2:?--manifest requires a path}"
      shift 2
      ;;
    --provenance)
      PROVENANCE_PATH="${2:?--provenance requires a path}"
      shift 2
      ;;
    --bundle-out)
      BUNDLE_OUT="${2:?--bundle-out requires a path}"
      shift 2
      ;;
    --zstd-level)
      ZSTD_LEVEL="${2:?--zstd-level requires an integer}"
      shift 2
      ;;
    --require-path)
      REQUIRED_PATHS+=("${2:?--require-path requires a relative path}")
      shift 2
      ;;
    --forbid-name)
      FORBIDDEN_NAMES+=("${2:?--forbid-name requires a file or directory name}")
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

mkdir -p "${LOG_DIR}"
ABS_ROOT="$(cd "${ROOT_DIR}" && pwd)"

json_escape() {
  python3 -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$1"
}

record_run() {
  local status="$1"
  local detail="$2"
  local ts_utc
  ts_utc="$(date -u +"%Y-%m-%dT%H-%M-%SZ")"

  printf '{"timestamp_utc":%s,"root":%s,"status":%s,"detail":%s}\n' \
    "$(json_escape "${ts_utc}")" \
    "$(json_escape "${ABS_ROOT}")" \
    "$(json_escape "${status}")" \
    "$(json_escape "${detail}")" >> "${LOG_FILE}"
}

on_error() {
  local exit_code="$?"
  record_run "FAILED" "exit_code=${exit_code}"
  exit "${exit_code}"
}

trap on_error ERR

AUDIT_CMD=(python3 scripts/local_workspace_audit.py --root "${ABS_ROOT}")
if [[ -n "${MANIFEST_PATH}" ]]; then
  AUDIT_CMD+=(--manifest "${MANIFEST_PATH}")
fi
for req_path in "${REQUIRED_PATHS[@]}"; do
  AUDIT_CMD+=(--require-path "${req_path}")
done
for bad_name in "${FORBIDDEN_NAMES[@]}"; do
  AUDIT_CMD+=(--forbid-name "${bad_name}")
done

GUARD_CMD=(python3 scripts/clean_pipeline_guard.py --root "${ABS_ROOT}")
if [[ -n "${PROVENANCE_PATH}" ]]; then
  GUARD_CMD+=(--provenance "${PROVENANCE_PATH}")
fi

echo "[1/4] Running local workspace & manifest audit..."
"${AUDIT_CMD[@]}"

echo "[2/4] Running clean pipeline & provenance guard..."
"${GUARD_CMD[@]}"

echo "[3/4] Running pytest suite..."
pytest -q

if [[ -n "${BUNDLE_OUT}" ]]; then
  echo "[4/4] Packaging deterministic bundle & verifying SHA-256 sidecar..."
  python3 scripts/package_bundle.py \
    --source "${ABS_ROOT}" \
    --out "${BUNDLE_OUT}" \
    --level "${ZSTD_LEVEL}"

  BUNDLE_DIR="$(cd "$(dirname "${BUNDLE_OUT}")" && pwd)"
  BUNDLE_FILE="$(basename "${BUNDLE_OUT}")"
  (cd "${BUNDLE_DIR}" && sha256sum -c "${BUNDLE_FILE}.sha256")
  record_run "PASSED" "bundle=${BUNDLE_OUT}"
else
  echo "[4/4] Skipping bundle packaging (no --bundle-out specified)."
  record_run "PASSED" "audit+guard+pytest"
fi

trap - ERR
echo "Master pipeline passed. Logged to ${LOG_FILE}"
tar.zst
chmod +x scripts/package_bundle.py

# 1. Build a checksummed .tar.zst bundle into build/
python3 scripts/package_bundle.py --source . --out build/workspace_bundle.tar.zst

# 2. Verify the bundle's own SHA-256 sidecar from build/
(cd build && sha256sum -c workspace_bundle.tar.zst.sha256)

# 3. Run your master pipeline with custom workspace rules
python3 scripts/local_workspace_audit.py \
  --root . \
  --manifest build/SHA256SUMS \
  --require-path README.md \
  --forbid-name .DS_Store
bundle.py
    parser.add_argument(
        "--require-path",
        action="append",
        default=[],
        help="Relative path that must exist under --root (repeatable)",
    )
    parser.add_argument(
        "--forbid-name",
        action="append",
        default=[],
        help="File or directory name forbidden under --root (repeatable)",
    )
# Add these helper checks inside audit_workspace(root, manifest, required_paths=(), forbidden_names=()):
    root_resolved = root.resolve()

    for req_rel in required_paths:
        req_target = (root_resolved / req_rel).resolve()
        if not req_target.exists():
            errors.append(f"Missing required workspace path: {req_rel}")

    if forbidden_names:
        forbidden_set = set(forbidden_names)
        ignored_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}
        for path in root_resolved.rglob("*"):
            if any(part in ignored_dirs for part in path.parts):
                continue
            if path.name in forbidden_set:
                errors.append(f"Forbidden workspace item found: {path.relative_to(root_resolved)}")
path.name
path.name
#!/usr/bin/env python3
"""Create a deterministic tar.zst archive and companion SHA-256 checksum file."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

EXCLUDED_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}


def _reset_tarinfo(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    if info.isdir():
        info.mode = 0o755
    elif info.isfile():
        info.mode = 0o644
    return info


def build_deterministic_tar(source_dir: Path, tar_path: Path) -> None:
    source_resolved = source_dir.resolve()
    files_and_dirs: list[tuple[Path, str]] = []

    for current_root, dirnames, filenames in os.walk(source_resolved):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
        filenames.sort()

        current_path = Path(current_root)
        rel_root = current_path.relative_to(source_resolved)

        if str(rel_root) != ".":
            files_and_dirs.append((current_path, rel_root.as_posix()))

        for fname in filenames:
            full_file = current_path / fname
            if full_file.is_symlink():
                continue
            arcname = fname if str(rel_root) == "." else f"{rel_root.as_posix()}/{fname}"
            files_and_dirs.append((full_file, arcname))

    with tarfile.open(tar_path, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for src_path, arcname in files_and_dirs:
            tf.add(src_path, arcname=arcname, recursive=False, filter=_reset_tarinfo)


def compress_zst(tar_path: Path, zst_path: Path, level: int = 3) -> None:
    zst_path.parent.mkdir(parents=True, exist_ok=True)
    with tar_path.open("rb") as src, zst_path.open("wb") as dst:
        subprocess.run(
            ["zstd", f"-{level}", "--force", "--stdout"],
            stdin=src,
            stdout=dst,
            check=True,
        )


def write_sha256_sidecar(artifact_path: Path, checksum_path: Path) -> str:
    h = hashlib.sha256()
    with artifact_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    digest = h.hexdigest()
    checksum_path.write_text(f"{digest}  {artifact_path.name}\n", encoding="utf-8")
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package deterministic tar.zst bundle + SHA-256.")
    parser.add_argument("--source", required=True, help="Directory to archive")
    parser.add_argument("--out", required=True, help="Output .tar.zst path")
    parser.add_argument("--level", type=int, default=3, help="zstd compression level (1-19)")
    args = parser.parse_args(argv)

    source_dir = Path(args.source)
    if not source_dir.is_dir():
        print(f"[BUNDLE FAIL] Source directory not found: {source_dir}", file=sys.stderr)
        return 1

    zst_path = Path(args.out)
    if not zst_path.name.endswith(".tar.zst"):
        print(f"[BUNDLE FAIL] Output path must end with .tar.zst: {zst_path}", file=sys.stderr)
        return 1

    checksum_path = Path(f"{zst_path}.sha256")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            raw_tar = Path(tmpdir) / "bundle.tar"
            build_deterministic_tar(source_dir, raw_tar)
            compress_zst(raw_tar, zst_path, level=args.level)
        digest = write_sha256_sidecar(zst_path, checksum_path)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        print(f"[BUNDLE FAIL] {exc}", file=sys.stderr)
        return 1

    print(f"[BUNDLE OK] archive={zst_path} sha256={digest} sidecar={checksum_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="."
MANIFEST_PATH=""
PROVENANCE_PATH=""
BUNDLE_OUT=""
ZSTD_LEVEL="${ZSTD_LEVEL:-3}"
LOG_DIR="${PIPELINE_LOG_DIR:-${HOME}/.local/state/master_pipeline}"
LOG_FILE="${LOG_DIR}/pipeline_runs.jsonl"

REQUIRED_PATHS=()
FORBIDDEN_NAMES=()

# Allow positional arguments first for backward compatibility:
#   run_master_pipeline.sh [ROOT_DIR] [MANIFEST_PATH] [PROVENANCE_PATH] [--flag value ...]
if [[ $# -gt 0 && "${1}" != --* ]]; then
  ROOT_DIR="${1}"
  shift
fi
if [[ $# -gt 0 && "${1}" != --* ]]; then
  MANIFEST_PATH="${1}"
  shift
fi
if [[ $# -gt 0 && "${1}" != --* ]]; then
  PROVENANCE_PATH="${1}"
  shift
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      ROOT_DIR="${2:?--root requires a path}"
      shift 2
      ;;
    --manifest)
      MANIFEST_PATH="${2:?--manifest requires a path}"
      shift 2
      ;;
    --provenance)
      PROVENANCE_PATH="${2:?--provenance requires a path}"
      shift 2
      ;;
    --bundle-out)
      BUNDLE_OUT="${2:?--bundle-out requires a path}"
      shift 2
      ;;
    --zstd-level)
      ZSTD_LEVEL="${2:?--zstd-level requires an integer}"
      shift 2
      ;;
    --require-path)
      REQUIRED_PATHS+=("${2:?--require-path requires a relative path}")
      shift 2
      ;;
    --forbid-name)
      FORBIDDEN_NAMES+=("${2:?--forbid-name requires a file or directory name}")
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

mkdir -p "${LOG_DIR}"
ABS_ROOT="$(cd "${ROOT_DIR}" && pwd)"

json_escape() {
  python3 -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$1"
}

record_run() {
  local status="$1"
  local detail="$2"
  local ts_utc
  ts_utc="$(date -u +"%Y-%m-%dT%H-%M-%SZ")"

  printf '{"timestamp_utc":%s,"root":%s,"status":%s,"detail":%s}\n' \
    "$(json_escape "${ts_utc}")" \
    "$(json_escape "${ABS_ROOT}")" \
    "$(json_escape "${status}")" \
    "$(json_escape "${detail}")" >> "${LOG_FILE}"
}

on_error() {
  local exit_code="$?"
  record_run "FAILED" "exit_code=${exit_code}"
  exit "${exit_code}"
}

trap on_error ERR

AUDIT_CMD=(python3 scripts/local_workspace_audit.py --root "${ABS_ROOT}")
if [[ -n "${MANIFEST_PATH}" ]]; then
  AUDIT_CMD+=(--manifest "${MANIFEST_PATH}")
fi
for req_path in "${REQUIRED_PATHS[@]}"; do
  AUDIT_CMD+=(--require-path "${req_path}")
done
for bad_name in "${FORBIDDEN_NAMES[@]}"; do
  AUDIT_CMD+=(--forbid-name "${bad_name}")
done

GUARD_CMD=(python3 scripts/clean_pipeline_guard.py --root "${ABS_ROOT}")
if [[ -n "${PROVENANCE_PATH}" ]]; then
  GUARD_CMD+=(--provenance "${PROVENANCE_PATH}")
fi

echo "[1/4] Running local workspace & manifest audit..."
"${AUDIT_CMD[@]}"

echo "[2/4] Running clean pipeline & provenance guard..."
"${GUARD_CMD[@]}"

echo "[3/4] Running pytest suite..."
pytest -q

if [[ -n "${BUNDLE_OUT}" ]]; then
  echo "[4/4] Packaging deterministic bundle & verifying SHA-256 sidecar..."
  python3 scripts/package_bundle.py \
    --source "${ABS_ROOT}" \
    --out "${BUNDLE_OUT}" \
    --level "${ZSTD_LEVEL}"

  BUNDLE_DIR="$(cd "$(dirname "${BUNDLE_OUT}")" && pwd)"
  BUNDLE_FILE="$(basename "${BUNDLE_OUT}")"
  (cd "${BUNDLE_DIR}" && sha256sum -c "${BUNDLE_FILE}.sha256")
  record_run "PASSED" "bundle=${BUNDLE_OUT}"
else
  echo "[4/4] Skipping bundle packaging (no --bundle-out specified)."
  record_run "PASSED" "audit+guard+pytest"
fi

trap - ERR
echo "Master pipeline passed. Logged to ${LOG_FILE}"
#!/usr/bin/env python3
"""Audit a local workspace directory, manifest checksums, and policy rules."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

IGNORED_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}


def parse_manifest(manifest_path: Path) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for line_no, raw_line in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = raw_line.rstrip("\r\n").split("  ", maxsplit=1)
        if len(parts) != 2:
            parts = raw_line.rstrip("\r\n").split(" *", maxsplit=1)
        if len(parts) != 2:
            raise ValueError(f"{manifest_path}:{line_no}: malformed manifest line")
        digest, rel_path = parts[0].strip().lower(), parts[1].strip()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError(f"{manifest_path}:{line_no}: invalid SHA-256 digest")
        entries.append((digest, rel_path))
    return entries


def sha256_file(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_within_root(target: Path, root_resolved: Path) -> bool:
    try:
        target.relative_to(root_resolved)
        return True
    except ValueError:
        return False


def audit_workspace(
    root: Path,
    manifest: Path | None,
    required_paths: tuple[str, ...] | list[str] = (),
    forbidden_names: tuple[str, ...] | list[str] = (),
) -> list[str]:
    errors: list[str] = []
    if not root.exists() or not root.is_dir():
        return [f"Root directory does not exist or is not a directory: {root}"]

    root_resolved = root.resolve()

    for req_rel in required_paths:
        req_target = (root_resolved / req_rel).resolve()
        if not _is_within_root(req_target, root_resolved):
            errors.append(f"Required path escapes root: {req_rel}")
            continue
        if not req_target.exists():
            errors.append(f"Missing required workspace path: {req_rel}")

    if forbidden_names:
        forbidden_set = set(forbidden_names)
        for path in root_resolved.rglob("*"):
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            if path.name in forbidden_set:
                errors.append(f"Forbidden workspace item found: {path.relative_to(root_resolved)}")

    if manifest is not None:
        if not manifest.is_file():
            errors.append(f"Manifest file not found: {manifest}")
            return errors
        try:
            entries = parse_manifest(manifest)
        except ValueError as exc:
            errors.append(str(exc))
            return errors

        for expected_digest, rel_path in entries:
            target = (root_resolved / rel_path).resolve()
            if not _is_within_root(target, root_resolved):
                errors.append(f"Manifest path escapes root: {rel_path}")
                continue
            if not target.is_file():
                errors.append(f"Missing manifest artifact: {rel_path}")
                continue
            actual_digest = sha256_file(target)
            if actual_digest != expected_digest:
                errors.append(
                    f"Checksum mismatch for {rel_path}: expected {expected_digest}, got {actual_digest}"
                )

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit local workspace and SHA256SUMS manifest.")
    parser.add_argument("--root", required=True, help="Repository or workspace root directory")
    parser.add_argument("--manifest", default="", help="Optional path to SHA256SUMS manifest")
    parser.add_argument(
        "--require-path",
        action="append",
        default=[],
        help="Relative path that must exist under --root (repeatable)",
    )
    parser.add_argument(
        "--forbid-name",
        action="append",
        default=[],
        help="File or directory name forbidden under --root (repeatable)",
    )
    args = parser.parse_args(argv)

    root = Path(args.root)
    manifest = Path(args.manifest) if args.manifest else None
    errors = audit_workspace(
        root=root,
        manifest=manifest,
        required_paths=args.require_path,
        forbidden_names=args.forbid_name,
    )

    if errors:
        for err in errors:
            print(f"[AUDIT FAIL] {err}", file=sys.stderr)
        return 1

    print(f"[AUDIT OK] root={root.resolve()}" + (f" manifest={manifest}" if manifest else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
chmod +x \
  scripts/run_master_pipeline.sh \
  scripts/local_workspace_audit.py \
  scripts/clean_pipeline_guard.py \
  scripts/package_bundle.py

bash scripts/run_master_pipeline.sh \
  --root . \
  --manifest build/SHA256SUMS \
  --provenance config/provenance.json \
  --require-path README.md \
  --forbid-name .DS_Store \
  --bundle-out build/workspace_bundle.tar.zst

tail -n 5 "${HOME}/.local/state/master_pipeline/pipeline_runs.jsonl"
pipeline.sh

<div align="center">

# 女娲.skill

<p align="center">
  <img src="assets/hero.gif" alt="女娲.skill 宣传动画" />
  <br/>
  <sub>动画由 huashu-motion 制作，女娲形象与每一种画风都由代码绘制</sub>
</p>

<!-- BOOK-PROMO-START 《图解Agent Skills》京东横幅，2026-12-21下线 -->
<a href="https://item.jd.com/14829817.html"><img src="https://raw.githubusercontent.com/alchaincyf/alchaincyf/main/assets/book-agent-skills-jd-c.jpg" alt="纸质书《图解Agent Skills：让AI记住你的工作方式》已上市，点击去京东购买" width="100%"></a>
<!-- BOOK-PROMO-END -->

> *「你想蒸馏的下一个员工，何必是同事」*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-Standard-green)](https://agentskills.io)
[![skills.sh](https://img.shields.io/badge/skills.sh-Compatible-blue)](https://skills.sh)
[![Multi-Runtime](https://img.shields.io/badge/Runtime-Claude%20Code%20·%20Codex%20·%20Cursor%20·%20OpenClaw%20·%20Hermes%20·%20DeepSeek%20Harness-blueviolet)](#安装)

<br>

**女娲帮你蒸馏任何人的思维方式，让乔布斯、马斯克、芒格、费曼都给你打工。**

<sub>基于开放的 [Agent Skills 协议](https://agentskills.io)，可在 Claude Code、Codex、Cursor、OpenClaw、Hermes Agent、CodeBuddy、Workbuddy、Gemini CLI、OpenCode、DeepSeek Harness 等 50+ 兼容 runtime 中运行。</sub>

<br>

[同事.skill](https://github.com/titanwings/colleague-skill) 证明了蒸馏一个人是可行的。<br>
那何必蒸馏同事？去蒸馏乔布斯、芒格、费曼、马斯克。<br>
只需输入一个名字，女娲自动完成调研、提炼、验证全流程。

[看效果](#效果示例) · [安装](#安装) · [它蒸馏了什么](#女娲蒸馏了什么) · [工作原理](#工作原理)

<br>

**其他语言 / Other Languages:**

[English](README_EN.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Español](README_ES.md)

<br>

[![Star History Chart](https://api.star-history.com/svg?repos=alchaincyf/nuwa-skill&type=Date)](https://star-history.com/#alchaincyf/nuwa-skill&Date)

</div>

---

## 效果示例

```
用户      ❯ 我同时想做自媒体、写书、做独立开发，精力完全不够

Naval     ❯ 你列了三个欲望。每个欲望都是你跟不快乐签的一份合同。
            不是精力不够，是合同太多。
            
            问你自己：哪一个做起来你会忘记时间？
            那个就是你的特定知识所在。
            
            不是三选一。是先一，再一，再一。
            串行复利，不是并行内耗。
```

```
用户      ❯ 我们的SaaS产品获客成本太高了

马斯克     ❯ 先别想怎么降。先算物理极限。
            获客的最小必要动作是什么？用户从知道你到付费，
            信息传递的理论最短路径是什么？
            
            现在你的实际路径是理论路径的几倍？
            如果超过3倍，中间一定有可以砍掉的步骤。
            不是优化漏斗，是质疑漏斗本身该不该存在。
```

再来一个大家更熟悉的。蒸馏乔布斯之后，问他「OpenAI和Anthropic谁的方向对」：

```
用户      ❯ OpenAI和Anthropic谁的方向是对的？

乔布斯    ❯ 你问错了。这不是一场关于方向的竞赛。
            这是一场关于品味的竞赛。

            OpenAI像1985年的微软。什么都做，什么都要赢。
            这种策略能赢市场份额。Bill Gates就是这么赢的。
            问题是——当你什么都做的时候，你不可能每件事都做到
            insanely great。

            Anthropic更像早期的Apple。聚焦。
            Focus means saying no to a hundred good ideas.

            但两家公司都犯了一个我绝对不会犯的错误——
            他们不控制硬件。

            最终赢的可能是同时控制芯片、模型和用户界面的人。
            你知道现在谁在同时做这三件事吗？Apple.
```

这不是角色扮演。乔布斯用的是「聚焦即说不」和「端到端控制」心智模型，Naval用的是「欲望即合同」，马斯克用的是「渐近极限法」。**它们不是在复读名人语录，是在用名人的认知框架帮你分析。**

---

## 安装

女娲基于开放的 [Agent Skills](https://agentskills.io) 协议，可在任何 skills-compatible 的 AI agent runtime 中运行。

### 方式一：一行命令（推荐，跨 runtime）

打开你正在用的 agent（Claude Code、Codex、Cursor、OpenClaw、Hermes、CodeBuddy、Workbuddy、Gemini CLI、OpenCode 等），告诉它：

```
帮我安装这个 skill：https://github.com/alchaincyf/nuwa-skill
```

或者用通用 CLI 安装器（[vercel-labs/skills](https://github.com/vercel-labs/skills)，支持 55+ runtime）：

```bash
npx skills add alchaincyf/nuwa-skill
```

它会自动识别你当前的 runtime 并把 skill 放到正确目录。需要指定时加 `-a claude-code` / `-a codex` / `-a cursor` / `-a openclaw` 等参数。

### 方式二：手动安装

<details>
<summary>展开查看各 runtime 的 skills 目录</summary>

| Runtime | 安装路径 |
|---|---|
| Claude Code | `~/.claude/skills/nuwa-skill/` |
| Codex CLI | `~/.codex/skills/nuwa-skill/` |
| Cursor | `~/.cursor/skills/nuwa-skill/` |
| OpenClaw | `~/.openclaw/workspace/skills/nuwa-skill/` |
| DeepSeek Harness | `~/.dsh/skills/nuwa-skill/` |
| Hermes Agent | 跑 `tools/install_hermes_skill.py` |
| 其他 runtime | clone 到对应 runtime 的 `skills/` 目录 |

```bash
git clone https://github.com/alchaincyf/nuwa-skill <上面对应的路径>
```

</details>

### DeepSeek Harness 插件

女娲也是一个 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）插件，一行命令装进你的 profile（以 `web` 为例），重新启动 DSH 后生效：

```bash
dsh plugin --profile web add github:alchaincyf/nuwa-skill
```

卸载：`dsh plugin --profile web remove huashu-nuwa`。在 DSH 里蒸馏出的人物 Skill 会写进项目的 `.dsh/skills/`，DSH 会自动加载。

### 方式三：作为参考资料使用

即使 runtime 不支持 Agent Skills 自动加载，你也可以直接把 `SKILL.md` 的内容粘贴进对话——它本质就是一份 markdown + YAML frontmatter。

---

### 使用

装好后，告诉 agent：

```
> 蒸馏一个保罗·格雷厄姆
> 造一个张小龙的视角Skill
> 帮我做一个段永平的Skill
```

造完之后直接调用：

```
> 用芒格的视角帮我分析这个投资决策
> 费曼会怎么解释量子计算？
> 切换到Naval，我在纠结三件事
```

---

## 女娲蒸馏了什么

蒸馏各领域最强的人，需要提取比日常工作习惯更深的东西。女娲提取五层：

| 层次 | 说明 |
|---|---|
| **怎么说话** | 表达DNA——语气、节奏、用词偏好 |
| **怎么想** | 心智模型、认知框架 |
| **怎么判断** | 决策启发式 |
| **什么不做** | 反模式、价值观底线 |
| **知道局限** | 诚实边界 |

工作习惯可以靠流程文档传递，但让芒格和马斯克面对同一个问题做出不同判断的，是认知框架。女娲提取的是认知操作系统。

### 诚实边界

每个Skill都明确标注做不到什么：

- 蒸馏不了直觉——框架能提取，灵感不能
- 捕捉不了突变——截止到调研时间的快照
- 公开表达 ≠ 真实想法——只能基于公开信息

**一个不告诉你局限在哪的Skill，不值得信任。**

---

## 已蒸馏人物

女娲已蒸馏了14位人物 + 1个主题。每个都是独立的、可直接安装使用的Skill，全部基于 Agent Skills 协议，可在 Claude Code / Codex / Cursor / OpenClaw / Hermes 等 runtime 通用：

### 人物Skill

| 人物 | 领域 | 独立仓库 | 一键安装（跨 runtime） |
|------|------|---------|---------|
| 🔥 **Paul Graham** | 创业/写作/产品/人生哲学 | [paul-graham-skill](https://github.com/alchaincyf/paul-graham-skill) | `npx skills add alchaincyf/paul-graham-skill` |
| 🔥 **张一鸣** | 产品/组织/全球化/人才 | [zhang-yiming-skill](https://github.com/alchaincyf/zhang-yiming-skill) | `npx skills add alchaincyf/zhang-yiming-skill` |
| 🔥 **Karpathy** | AI/工程/教育/开源 | [karpathy-skill](https://github.com/alchaincyf/karpathy-skill) | `npx skills add alchaincyf/karpathy-skill` |
| 🔥 **Ilya Sutskever** | AI安全/scaling/研究品味 | [ilya-sutskever-skill](https://github.com/alchaincyf/ilya-sutskever-skill) | `npx skills add alchaincyf/ilya-sutskever-skill` |
| 🔥 **MrBeast** | 内容创造/YouTube方法论 | [mrbeast-skill](https://github.com/alchaincyf/mrbeast-skill) | `npx skills add alchaincyf/mrbeast-skill` |
| 🔥 **特朗普** | 谈判/权力/传播/行为预判 | [trump-skill](https://github.com/alchaincyf/trump-skill) | `npx skills add alchaincyf/trump-skill` |
| ⭐ **乔布斯** | 产品/设计/战略 | [steve-jobs-skill](https://github.com/alchaincyf/steve-jobs-skill) | `npx skills add alchaincyf/steve-jobs-skill` |
| **马斯克** | 工程/成本/第一性原理 | [elon-musk-skill](https://github.com/alchaincyf/elon-musk-skill) | `npx skills add alchaincyf/elon-musk-skill` |
| **芒格** | 投资/多元思维/逆向思考 | [munger-skill](https://github.com/alchaincyf/munger-skill) | `npx skills add alchaincyf/munger-skill` |
| **费曼** | 学习/教学/科学思维 | [feynman-skill](https://github.com/alchaincyf/feynman-skill) | `npx skills add alchaincyf/feynman-skill` |
| **纳瓦尔** | 财富/杠杆/人生哲学 | [naval-skill](https://github.com/alchaincyf/naval-skill) | `npx skills add alchaincyf/naval-skill` |
| **塔勒布** | 风险/反脆弱/不确定性 | [taleb-skill](https://github.com/alchaincyf/taleb-skill) | `npx skills add alchaincyf/taleb-skill` |
| **张雪峰** | 教育选择/职业规划/阶层流动 | [zhangxuefeng-skill](https://github.com/alchaincyf/zhangxuefeng-skill) | `npx skills add alchaincyf/zhangxuefeng-skill` |
| **孙宇晨** | 营销/注意力经济/叙事操控 | [仓库内examples/](examples/sun-yuchen-perspective/) | 复制 `examples/sun-yuchen-perspective/` 到skills目录 |

### 主题Skill

| 主题 | 领域 | 独立仓库 | 一键安装（跨 runtime） |
|------|------|---------|---------|
| **X导师** | X/Twitter运营全栈 | [x-mentor-skill](https://github.com/alchaincyf/x-mentor-skill) | `npx skills add alchaincyf/x-mentor-skill` |

人物Skill蒸馏一个人的思维方式；主题Skill蒸馏一个领域的方法论。每个仓库都包含完整的调研数据和效果示例对话。

🧪 **保真度评分卡**：15个官方Skill已全部通过独立双agent盲测（立场一致性/风格辨识度/边缘诚实度/来源透明度/结构完整度，方法论见 [references/fidelity-scorecard.md](references/fidelity-scorecard.md)），**全员A级（≥85分）**。各分数：MrBeast/纳瓦尔/塔勒布/乔布斯/Karpathy/Paul Graham/张雪峰 97 · 芒格/费曼/X导师 96 · 特朗普 95 · Ilya 94 · 张一鸣 93 · 孙宇晨 91 · 马斯克 89。完整评分卡见各skill目录内的 `FIDELITY.md`。

想蒸馏不在列表里的人或主题？安装女娲，说「蒸馏一个XXX」就行。

---

## 贡献与社区

女娲的生态由社区一起长大，但走两条不同的路：

- **`SKILL.md` 是核心资产，不接受外部PR改动**。发现方法论的bug或改进点→开issue讨论，被采纳的想法由维护者实现并在commit中致谢（先例见PR #59）
- **社区蒸馏的人物skill走 [COMMUNITY.md](COMMUNITY.md) 索引**：放你自己的仓库（star归你），跑一遍[保真度评分卡](references/fidelity-scorecard.md)拿到B级以上，提一行PR即可收录

完整规则见 [CONTRIBUTING.md](CONTRIBUTING.md)。社区已有的合集、多人格编排和主题应用，见 [COMMUNITY.md](COMMUNITY.md)。

---

## 达尔文.skill：让所有Skill持续进化

<div align="center">

<a href="https://github.com/alchaincyf/darwin-skill">
<img src="https://raw.githubusercontent.com/alchaincyf/darwin-skill/master/assets/banner.svg" alt="达尔文.skill" width="600">
</a>

</div>

女娲造Skill，**[达尔文](https://github.com/alchaincyf/darwin-skill)** 让Skill进化。

受 Karpathy autoresearch 启发，达尔文.skill 用自主实验循环批量优化所有Skill：8维度评估、棘轮机制（只保留改进，自动回滚退步）、独立子agent评分。女娲的 Phase 5 双Agent精炼就内置了达尔文的评估体系，这也是女娲生成的Skill质量高的原因之一。

```bash
npx skills add alchaincyf/darwin-skill
```

---

## 工作原理

输入一个名字后，女娲做五件事：

**1. 先写先验快照**——调研之前，先把模型不查资料就知道的内容写下来。之后的调研只找三种东西：推翻它的、比它深的、它没有的。模型本来就答得出的内容，不占Skill的篇幅。

**2. 采集与封存**——著作、播客/访谈、社交媒体、批评者视角、决策记录、人生时间线，各自存档。同时封存一批此人真实做过的决策和完整回答，不给提炼环节看，留到最后当考题。

**3. 提炼**——5–8个招式（遇到某类问题时他具体怎么做）、3–7个心智模型、决策启发式、带出处的案例卡、至少2条常见误读、声音、张力与边界。心智模型仍要过三重验证：跨2+个领域出现过、能推断对新问题的立场、不是所有聪明人都会这么想。

**4. 成形**——产物分三层：350行以内的SKILL.md、案例库 `references/casebook.md`、原话库 `references/voice.md`。每个Skill自带七条运行纪律，比如「材料里没有，不等于他没说过」「原话和推演分开说」。

**5. 验证**——由独立agent盲测：同一组任务题，带Skill和不带Skill各答一遍，评审不知道哪份是哪份；再加封存题和边界题。结果写进FIDELITY.md，输了也照写。

两种走法：能力强的模型按每一步的过关条件放手做，轻量模型照 `references/` 里的手册一步步走。v1.x 造出来的Skill可以说「升级XX」，调研底稿还在就不用重新调研。`examples/` 里芒格和乔布斯两个示例已升到v2，其余仍是v1格式。

方法细节在 `references/`：`research-playbook.md`（采集）、`extraction-framework.md`（提炼）、`validation-playbook.md`（验证）。

---

## 仓库结构

```
nuwa-skill/
├── SKILL.md                      # 女娲本体
├── references/
│   ├── extraction-framework.md   # 提炼方法论（想深入了解看这个）
│   ├── research-playbook.md / validation-playbook.md / diagnose-playbook.md
│   ├── special-cases.md / fidelity-scorecard.md
│   └── skill-template.md         # 生成Skill的模板
└── examples/                          # 13个人物 + 1个主题，含完整调研数据
    ├── steve-jobs-perspective/        # ⭐ 乔布斯（含实战对话记录）
    ├── paul-graham-perspective/       # Paul Graham
    ├── zhang-yiming-perspective/      # 张一鸣
    ├── andrej-karpathy-perspective/   # Karpathy
    ├── ilya-sutskever-perspective/    # Ilya Sutskever
    ├── trump-perspective/             # 特朗普
    ├── mrbeast-perspective/           # MrBeast
    ├── elon-musk-perspective/         # 马斯克
    ├── munger-perspective/            # 查理·芒格
    ├── feynman-perspective/           # 费曼
    ├── naval-perspective/             # Naval Ravikant
    ├── taleb-perspective/             # 塔勒布
    └── x-mastery-mentor/             # X导师（主题Skill）
```

调研过程全透明。每个example都包含完整的调研文件，你可以看到信息怎么被收集、筛选、变成心智模型。乔布斯的示例还附带了一段完整的实战对话记录（聊AI硬件、OpenAI vs Anthropic、Apple破局），展示Skill在多轮深度对话中的表现。

---

## 背后的故事

[同事.skill](https://github.com/titanwings/colleague-skill) 最近在GitHub爆火——把离职同事蒸馏成AI Skill，几天破5000星。它证明了一件事：蒸馏一个人是完全可行的。

既然我们有了蒸馏人的能力，为什么只蒸馏身边的同事？去蒸馏各领域最强的人。而且幸运的是，这些人通常留下了大量可以被蒸馏的材料——著作、演讲、访谈、社交媒体。这是对自己能力的极大补充。

我之前就一直在做类似的事，但蒸馏的不是同事，是芒格、费曼、Naval、马斯克、塔勒布这些人。今天把方法论开源了。

女娲不复制人。它提取认知操作系统。

**女娲（Nuwa）**，中国神话里用泥土造人的女神。这里的泥土是公开信息，造出来的不是人，是一面镜子。

---

## 关于作者

**花叔 Huashu** — AI Native Coder，独立开发者，代表作：小猫补光灯（AppStore 付费榜 Top1）

| 平台 | 链接 |
|------|------|
| 🌐 官网 | [bookai.top](https://bookai.top) · [huasheng.ai](https://www.huasheng.ai) |
| 𝕏 Twitter | [@AlchainHust](https://x.com/AlchainHust) |
| 📺 B站 | [花叔](https://space.bilibili.com/14097567) |
| ▶️ YouTube | [@Alchain](https://www.youtube.com/@Alchain) |
| 📕 小红书 | [花叔](https://www.xiaohongshu.com/user/profile/5abc6f17e8ac2b109179dfdf) |
| 💬 公众号 | 微信搜「花叔」或扫码关注 ↓ |

<img src="wechat-qrcode.jpg" alt="公众号二维码" width="360">

## 许可证

MIT — 随便用，随便改，随便造。

---

<div align="center">

**同事.skill** 蒸馏了人做什么。<br>
**女娲** 蒸馏了人怎么想。<br><br>
*你想蒸馏的下一个员工，何必是同事。*

<br>

MIT License © [花叔 Huashu](https://github.com/alchaincyf)

</div>

---

<div align="center">
<sub>作者的其他项目 · also by 花叔</sub>

[![FanBox · Coding Agent 的驾驶舱](https://raw.githubusercontent.com/alchaincyf/fanbox/master/assets/promo-banner.jpg)](https://github.com/alchaincyf/fanbox)

</div>

---

## English

> *"The next person you want to distill doesn't have to be a colleague."*

**[colleague-skill](https://github.com/titanwings/colleague-skill)** proved that distilling a person into an AI skill is viable. **Nuwa** asks: why stop at colleagues? Distill the best minds in every field — Munger, Feynman, Musk, Naval — people who conveniently left mountains of distillable material behind.

Nuwa is an [Agent Skill](https://agentskills.io) that extracts cognitive frameworks — mental models, decision heuristics, expression DNA — from any public figure into a runnable perspective skill. Works in Claude Code, Codex, Cursor, OpenClaw, Hermes Agent, CodeBuddy, Workbuddy, Gemini CLI, OpenCode, and 50+ skills-compatible runtimes.

Not role-playing. Cognitive architecture extraction.

**Install** (cross-runtime, auto-detects your agent): `npx skills add alchaincyf/nuwa-skill`

**DeepSeek Harness**: `dsh plugin --profile web add github:alchaincyf/nuwa-skill`, then restart DSH. Remove with `dsh plugin --profile web remove huashu-nuwa`.

**How it works**: Input a name → 6 parallel research agents → 40+ primary sources → triple-verified mental models → quality-validated SKILL.md

**13 person skills + 1 topic skill included** — all with full research data. The Jobs example includes a complete multi-turn conversation demo.

See the Chinese README above for live examples and methodology.
