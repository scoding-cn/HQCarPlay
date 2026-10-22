#!/usr/bin/env python3
"""Fetch the exact lwIP source used by the userspace NCM relay.

Requires git and network access for the first build. Subsequent builds reuse the
verified checkout; never download from unpinned HEAD.
"""
from pathlib import Path
import subprocess
import tempfile
import shutil

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "shared/src/main/jni/lwip"
COMMIT = "6ca936f6b588cee702c638eee75c2436e6cf75de"  # STABLE-2_1_3_RELEASE
# Upstream first, then read-only mirrors for networks that reset git-over-https to github.com.
REPOS = [
    "https://github.com/lwip-tcpip/lwip.git",
    "https://gitee.com/mirrors/lwip.git",
    "https://ghproxy.net/https://github.com/lwip-tcpip/lwip.git",
]

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)

def fetch(checkout):
    last = None
    for repo in REPOS:
        try:
            print(f"lwIP source: trying {repo}")
            run("git", "clone", "--no-checkout", repo, str(checkout))
            run("git", "-C", str(checkout), "checkout", "--detach", COMMIT)
        except subprocess.CalledProcessError as exc:
            last = exc
            print(f"lwIP source: {repo} failed, trying next")
            if checkout.exists():
                shutil.rmtree(checkout)
            continue
        # Any remote is accepted only if it yields the exact pinned revision.
        actual = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
        if actual != COMMIT:
            raise RuntimeError(f"Unexpected lwIP revision from {repo}: {actual}")
        print(f"lwIP source: fetched from {repo}")
        return
    raise RuntimeError("Unable to fetch lwIP from any known remote") from last

def main():
    marker = DEST / ".diplay-lwip-commit"
    if marker.is_file() and marker.read_text().strip() == COMMIT and (DEST / "src/include/lwip/opt.h").is_file():
        return
    with tempfile.TemporaryDirectory(prefix="diplay-lwip-") as td:
        checkout = Path(td) / "lwip"
        fetch(checkout)
        if DEST.exists():
            shutil.rmtree(DEST)
        shutil.copytree(checkout, DEST, ignore=shutil.ignore_patterns(".git"))
        marker.write_text(COMMIT + "\n")
    for f in ("src/include/lwip/opt.h", "src/include/lwip/tcp.h", "src/core/init.c"):
        if not (DEST / f).is_file():
            raise RuntimeError(f"Missing lwIP source: {f}")

if __name__ == "__main__":
    main()
