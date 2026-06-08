#!/usr/bin/env python3
"""
Script to query MalwareBazaar for similar Mirai IOT botnet samples.
"""
import argparse
import csv
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pyzipper
import requests


API_URL = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = b"infected"

DEFAULT_SEED = "0ea04179b34505024e111f254542d43f53765dc03f784e1efd10a88893e52662"


def api_post(data: dict, api_key: str, timeout: int = 60) -> requests.Response:
    headers = {"Auth-Key": api_key}

    for attempt in range(1, 8):
        try:
            r = requests.post(API_URL, data=data, headers=headers, timeout=timeout)

            if r.status_code in (429, 500, 502, 503, 504):
                wait = attempt * 15
                print(f"[!] API HTTP {r.status_code}; retrying in {wait}s... attempt {attempt}/7")
                time.sleep(wait)
                continue

            return r

        except requests.RequestException as e:
            wait = attempt * 15
            print(f"[!] API request failed: {e}; retrying in {wait}s... attempt {attempt}/7")
            time.sleep(wait)

    raise RuntimeError("MalwareBazaar API failed after 7 attempts")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_file(path: Path) -> str:
    result = subprocess.run(
        ["file", "-b", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return result.stdout.strip()


def is_target_file(file_output: str) -> bool:
    """
    Keep files matching the 0ea04179 ground-truth architecture:
      ELF 32-bit MSB executable, MIPS, MIPS-I, statically linked
    Stripped/not-stripped does not matter here; we want stripped relatives for BSim.
    """
    s = file_output.lower()

    return (
        "elf 32-bit msb executable" in s
        and "mips" in s
        and "mips-i" in s
        and "statically linked" in s
    )


def get_json_or_none(response: requests.Response):
    if response.status_code != 200:
        print(f"[!] HTTP {response.status_code}")
        print(response.text[:300])
        return None

    try:
        return response.json()
    except json.JSONDecodeError:
        print("[!] API did not return JSON:")
        print(response.text[:500])
        return None


def get_info(api_key: str, seed_hash: str) -> dict | None:
    print(f"[*] Getting seed info for {seed_hash}")

    r = api_post(
        {"query": "get_info", "hash": seed_hash},
        api_key,
        timeout=60,
    )

    data = get_json_or_none(r)
    if not data:
        return None

    if data.get("query_status") != "ok":
        print(f"[!] get_info status: {data.get('query_status')}")
        return None

    rows = data.get("data", [])
    if not rows:
        print("[!] No data returned for seed")
        return None

    return rows[0]


def query_by_telfhash(api_key: str, telfhash: str, limit: int) -> list[dict]:
    if not telfhash:
        return []

    print(f"[*] Querying by telfhash: {telfhash}")

    r = api_post(
        {"query": "get_telfhash", "telfhash": telfhash, "limit": str(limit)},
        api_key,
        timeout=60,
    )

    data = get_json_or_none(r)
    if not data:
        return []

    if data.get("query_status") != "ok":
        print(f"[!] get_telfhash status: {data.get('query_status')}")
        return []

    return data.get("data", [])


def query_by_tlsh(api_key: str, tlsh: str, limit: int) -> list[dict]:
    if not tlsh:
        return []

    print(f"[*] Querying by tlsh: {tlsh}")

    r = api_post(
        {"query": "get_tlsh", "tlsh": tlsh, "limit": str(limit)},
        api_key,
        timeout=60,
    )

    data = get_json_or_none(r)
    if not data:
        return []

    if data.get("query_status") != "ok":
        print(f"[!] get_tlsh status: {data.get('query_status')}")
        return []

    return data.get("data", [])


def query_mirai_name_cluster(api_key: str, seed_name: str, limit: int) -> list[dict]:
    """
    Fallback broad query. We filter locally for names close to the ground truth:
      iran.mipsrouter, update.mipsrouter, boatnet.mipsrouter, etc.
    """
    print("[*] Querying broad Mirai signature for filename cluster")

    r = api_post(
        {"query": "get_siginfo", "signature": "Mirai", "limit": str(limit)},
        api_key,
        timeout=60,
    )

    data = get_json_or_none(r)
    if not data:
        return []

    if data.get("query_status") != "ok":
        print(f"[!] get_siginfo status: {data.get('query_status')}")
        return []

    tokens = {"mipsrouter", "router", "iran", "boatnet", "update"}

    rows = []
    for item in data.get("data", []):
        name = (item.get("file_name") or "").lower()
        arch = (item.get("file_arch") or "").lower()
        ftype = (item.get("file_type") or "").lower()

        if arch != "mips":
            continue
        if ftype != "elf":
            continue
        if any(tok in name for tok in tokens):
            rows.append(item)

    return rows


def candidate_score(item: dict, seed_info: dict) -> int:
    """
    Higher score = closer to seed.
    """
    score = 0

    name = (item.get("file_name") or "").lower()
    arch = (item.get("file_arch") or "").lower()
    ftype = (item.get("file_type") or "").lower()
    sig = (item.get("signature") or "").lower()

    seed_name = (seed_info.get("file_name") or "").lower()
    seed_size = int(seed_info.get("file_size") or 0)
    item_size = int(item.get("file_size") or 0)

    if arch == "mips":
        score += 20
    if ftype == "elf":
        score += 20
    if sig == "mirai":
        score += 10

    if name == seed_name:
        score += 50
    if "mipsrouter" in name:
        score += 40
    if "iran" in name:
        score += 30
    if "update.mipsrouter" in name or "boatnet.mipsrouter" in name:
        score += 25
    if "mipsel" in name or "mpsl" in name:
        score -= 100

    if seed_size and item_size:
        diff = abs(seed_size - item_size)
        if diff == 0:
            score += 40
        elif diff <= 256:
            score += 30
        elif diff <= 2048:
            score += 15
        elif diff <= 10000:
            score += 5
        else:
            score -= 20

    return score


def dedupe_and_rank(rows: list[dict], seed_info: dict, seed_hash: str) -> list[dict]:
    by_hash = {}

    for item in rows:
        h = (item.get("sha256_hash") or "").lower()
        if len(h) != 64:
            continue

        # Skip the actual ground-truth sample; you already have it.
        if h == seed_hash.lower():
            continue

        old = by_hash.get(h)
        if old is None:
            by_hash[h] = item

    ranked = list(by_hash.values())
    ranked.sort(key=lambda x: candidate_score(x, seed_info), reverse=True)
    return ranked


def download_zip(api_key: str, sha256: str, zip_path: Path) -> bool:
    if zip_path.exists() and zip_path.stat().st_size > 0:
        return True

    r = api_post(
        {"query": "get_file", "sha256_hash": sha256},
        api_key,
        timeout=180,
    )

    if r.status_code != 200:
        print(f"[!] Download HTTP {r.status_code} for {sha256}")
        return False

    content = r.content

    if not content.startswith(b"PK"):
        print(f"[!] Non-ZIP/API error for {sha256}:")
        print(content[:300].decode(errors="replace"))
        return False

    zip_path.write_bytes(content)
    return True


def extract_zip(zip_path: Path, extract_dir: Path) -> list[Path]:
    extract_dir.mkdir(parents=True, exist_ok=True)
    extracted = []

    try:
        with pyzipper.AESZipFile(zip_path) as zf:
            zf.pwd = ZIP_PASSWORD

            for name in zf.namelist():
                safe_name = Path(name).name
                if not safe_name:
                    continue

                out_path = extract_dir / safe_name

                with zf.open(name) as src, out_path.open("wb") as dst:
                    shutil.copyfileobj(src, dst)

                extracted.append(out_path)

    except Exception as e:
        print(f"[!] Extract failed for {zip_path.name}: {e}")

    return extracted


def safe_delete(path: Path) -> None:
    try:
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    except Exception as e:
        print(f"[!] Could not delete {path}: {e}")


def load_seen_hashes(log_path: Path) -> set[str]:
    seen = set()

    if not log_path.exists():
        return seen

    try:
        with log_path.open("r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                h = (row.get("sha256_api") or "").strip().lower()
                if len(h) == 64:
                    seen.add(h)
    except Exception as e:
        print(f"[!] Could not read log: {e}")

    return seen


def count_existing_good(out_dir: Path) -> int:
    count = 0

    for p in out_dir.glob("*.elf"):
        if is_target_file(run_file(p)):
            count += 1

    return count


def main():
    parser = argparse.ArgumentParser(
        description="Find MalwareBazaar samples similar to a not-stripped MIPS-I ground truth sample."
    )

    parser.add_argument(
        "--seed",
        default=DEFAULT_SEED,
        help="Ground-truth SHA256 seed. Default is 0ea04179 iran.mipsrouter.",
    )

    parser.add_argument(
        "--out",
        default="/mnt/c/Users/tmg10/Documents/MalwareSamples/GroundTruthSimilar_0ea04179",
        help="Output directory for kept similar samples.",
    )

    parser.add_argument(
        "--want",
        type=int,
        default=15,
        help="Stop after keeping this many matching similar samples.",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=1000,
        help="API result limit for telfhash/tlsh/signature queries.",
    )

    parser.add_argument(
        "--sleep",
        type=float,
        default=1.0,
        help="Seconds to sleep between downloads.",
    )

    parser.add_argument(
        "--keep-zips",
        action="store_true",
        help="Keep downloaded ZIPs.",
    )

    args = parser.parse_args()

    api_key = os.environ.get("MB_API_KEY")
    if not api_key:
        print("[!] Set your MalwareBazaar API key first:")
        print('    export MB_API_KEY="YOUR-AUTH-KEY-HERE"')
        sys.exit(1)

    seed_hash = args.seed.lower()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    work_dir = out_dir / "_mb_work"
    zip_dir = work_dir / "zips"
    tmp_dir = work_dir / "tmp_extract"
    zip_dir.mkdir(parents=True, exist_ok=True)

    log_path = out_dir / "groundtruth_similar_log.csv"
    seen_hashes = load_seen_hashes(log_path)

    seed_info = get_info(api_key, seed_hash)
    if not seed_info:
        print("[!] Could not get seed info.")
        sys.exit(1)

    print("\n[*] Ground truth seed:")
    print(f"    sha256:   {seed_info.get('sha256_hash')}")
    print(f"    name:     {seed_info.get('file_name')}")
    print(f"    size:     {seed_info.get('file_size')}")
    print(f"    arch:     {seed_info.get('file_arch')}")
    print(f"    sig:      {seed_info.get('signature')}")
    print(f"    tlsh:     {seed_info.get('tlsh')}")
    print(f"    telfhash: {seed_info.get('telfhash')}")
    print()

    rows = []
    rows.extend(query_by_telfhash(api_key, seed_info.get("telfhash"), args.limit))
    rows.extend(query_by_tlsh(api_key, seed_info.get("tlsh"), args.limit))
    rows.extend(query_mirai_name_cluster(api_key, seed_info.get("file_name") or "", args.limit))

    candidates = dedupe_and_rank(rows, seed_info, seed_hash)

    if not candidates:
        print("[!] No candidates found.")
        sys.exit(1)

    print(f"[*] Ranked candidates: {len(candidates)}")
    print("[*] Top candidates:")
    for item in candidates[:25]:
        print(
            f"    score={candidate_score(item, seed_info):3d} "
            f"{item.get('sha256_hash')} "
            f"{item.get('file_name')} "
            f"size={item.get('file_size')} "
            f"arch={item.get('file_arch')}"
        )

    existing_good = count_existing_good(out_dir)
    print(f"\n[*] Existing good samples in output: {existing_good}")
    print(f"[*] Already tried hashes in log: {len(seen_hashes)}")

    kept = existing_good

    with log_path.open("a", newline="") as f:
        writer = csv.writer(f)

        if log_path.stat().st_size == 0:
            writer.writerow([
                "sha256_api",
                "sha256_actual",
                "status",
                "score",
                "metadata_name",
                "metadata_size",
                "file_output",
                "path_or_reason",
            ])

        for item in candidates:
            if kept >= args.want:
                break

            h = (item.get("sha256_hash") or "").lower()
            score = candidate_score(item, seed_info)
            name = item.get("file_name")
            size = item.get("file_size")

            if h in seen_hashes:
                print(f"[=] Skip already tried {h} {name}")
                continue

            print(f"\n[*] Downloading score={score} {h} {name} size={size}")

            zip_path = zip_dir / f"{h}.zip"

            if not download_zip(api_key, h, zip_path):
                writer.writerow([h, "", "download_failed", score, name, size, "", ""])
                time.sleep(args.sleep)
                continue

            safe_delete(tmp_dir)
            tmp_dir.mkdir(parents=True, exist_ok=True)

            extracted = extract_zip(zip_path, tmp_dir)

            if not extracted:
                writer.writerow([h, "", "extract_failed", score, name, size, "", ""])
                if not args.keep_zips:
                    safe_delete(zip_path)
                time.sleep(args.sleep)
                continue

            matched_this_hash = False

            for sample in extracted:
                if not sample.is_file():
                    continue

                file_out = run_file(sample)
                actual_hash = sha256_file(sample)

                if is_target_file(file_out):
                    final_path = out_dir / f"{actual_hash}.elf"

                    if final_path.exists():
                        print(f"[=] Duplicate already kept: {final_path.name}")
                        safe_delete(sample)
                    else:
                        shutil.move(str(sample), str(final_path))
                        final_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

                        print(f"[+] KEEP {final_path.name}")
                        print(f"    {file_out}")

                        writer.writerow([
                            h,
                            actual_hash,
                            "kept",
                            score,
                            name,
                            size,
                            file_out,
                            str(final_path),
                        ])

                        kept += 1
                        matched_this_hash = True

                        if kept >= args.want:
                            break

                else:
                    print(f"[-] Reject {sample.name}")
                    print(f"    {file_out}")

                    writer.writerow([
                        h,
                        actual_hash,
                        "rejected_deleted",
                        score,
                        name,
                        size,
                        file_out,
                        "deleted",
                    ])

                    safe_delete(sample)

            safe_delete(tmp_dir)

            if not args.keep_zips:
                safe_delete(zip_path)

            if not matched_this_hash:
                print("[*] No matching MIPS-I MSB static ELF in this ZIP.")

            print(f"[*] Kept so far: {kept}/{args.want}")
            time.sleep(args.sleep)

    print("\n[*] Done.")
    print(f"[*] Ground truth seed: {seed_hash}")
    print(f"[*] Similar samples kept: {kept}")
    print(f"[*] Output directory: {out_dir}")
    print(f"[*] Log: {log_path}")
    print("\nCheck with:")
    print(f"    file {out_dir}/*.elf")


if __name__ == "__main__":
    main()
