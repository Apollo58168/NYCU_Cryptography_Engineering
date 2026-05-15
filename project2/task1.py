#!/usr/bin/env python3
"""
Project 2 - Task 1: Single Hash vs. Merkle Tree Baseline

This program compares two integrity mechanisms for a 128 MiB file:

1. Single hash:
   SHA-256(test_128mb.bin)

2. Merkle Tree:
   - Split the file into 128 blocks of 1 MiB each.
   - Leaf hash  = SHA-256(block_i)
   - Parent hash = SHA-256(left_child_hash || right_child_hash)
   - Root hash is the final Merkle root.

The tree format intentionally matches data_gen/export_trusted_merkle_tree.py.
The script also reports the memory overhead of storing internal nodes, which is
required by the Task 1 specification.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_INPUT_FILE = "test_128mb.bin"
DEFAULT_TRUSTED_TREE_FILE = "trusted_merkle_tree.bin"
NUM_BLOCKS = 128
BLOCK_SIZE = 1024 * 1024
TOTAL_SIZE = NUM_BLOCKS * BLOCK_SIZE
HASH_SIZE = hashlib.sha256().digest_size
DEFAULT_RUNS = 3


@dataclass(frozen=True)
class TimedHash:
    hex_digest: str
    seconds: float


@dataclass(frozen=True)
class MerkleTreeResult:
    levels: list[list[bytes]]
    seconds: float

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    @property
    def leaf_count(self) -> int:
        return len(self.levels[0])

    @property
    def height(self) -> int:
        return len(self.levels) - 1

    @property
    def internal_node_count(self) -> int:
        return sum(len(level) for level in self.levels[1:])

    @property
    def total_node_count(self) -> int:
        return sum(len(level) for level in self.levels)

    @property
    def internal_node_memory_bytes(self) -> int:
        return self.internal_node_count * HASH_SIZE

    @property
    def total_tree_storage_bytes(self) -> int:
        return self.total_node_count * HASH_SIZE

    @property
    def proof_size_bytes(self) -> int:
        return self.height * HASH_SIZE


@dataclass(frozen=True)
class BenchmarkStats:
    values: list[float]

    @property
    def mean(self) -> float:
        return statistics.mean(self.values)

    @property
    def best(self) -> float:
        return min(self.values)

    @property
    def worst(self) -> float:
        return max(self.values)

    @property
    def stdev(self) -> float:
        if len(self.values) < 2:
            return 0.0
        return statistics.stdev(self.values)


@dataclass(frozen=True)
class Task1Result:
    single_hash: str
    single_hash_times: BenchmarkStats
    merkle_root: str
    merkle_times: BenchmarkStats
    leaf_count: int
    height: int
    internal_node_count: int
    internal_memory_bytes: int
    total_node_count: int
    total_tree_storage_bytes: int
    proof_size_bytes: int
    trusted_root: str | None


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def format_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} bytes"
    if size < 1024 * 1024:
        return f"{size / 1024:.2f} KiB"
    return f"{size / (1024 * 1024):.2f} MiB"


def format_time(seconds: float) -> str:
    return f"{seconds:.6f} s"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# File validation and reading
# ---------------------------------------------------------------------------

def validate_input_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(
            f"Input file not found: {path}\n"
            "Generate it first with:\n"
            "  python data_gen/generate_128mb.py"
        )

    actual_size = path.stat().st_size
    if actual_size != TOTAL_SIZE:
        raise ValueError(
            f"Invalid input size for {path}: expected {TOTAL_SIZE:,} bytes "
            f"({format_bytes(TOTAL_SIZE)}), got {actual_size:,} bytes "
            f"({format_bytes(actual_size)})."
        )


def iter_blocks(path: Path) -> Iterable[bytes]:
    with path.open("rb") as file:
        for block_index in range(NUM_BLOCKS):
            block = file.read(BLOCK_SIZE)
            if len(block) != BLOCK_SIZE:
                raise ValueError(
                    f"Unexpected block size at block {block_index}: "
                    f"expected {BLOCK_SIZE:,} bytes, got {len(block):,} bytes."
                )
            yield block

        trailing = file.read(1)
        if trailing:
            raise ValueError("Input file contains more data than expected.")


# ---------------------------------------------------------------------------
# Task 1 computations
# ---------------------------------------------------------------------------

def compute_single_hash(path: Path, chunk_size: int = 4 * 1024 * 1024) -> TimedHash:
    digest = hashlib.sha256()
    start = time.perf_counter()

    with path.open("rb") as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)

    return TimedHash(digest.hexdigest(), time.perf_counter() - start)


def build_merkle_tree(path: Path) -> MerkleTreeResult:
    start = time.perf_counter()

    levels: list[list[bytes]] = []
    current_level = [sha256(block) for block in iter_blocks(path)]
    levels.append(current_level)

    while len(current_level) > 1:
        if len(current_level) % 2 != 0:
            raise ValueError("Merkle construction expects an even node count at every level.")

        next_level = [
            sha256(current_level[i] + current_level[i + 1])
            for i in range(0, len(current_level), 2)
        ]
        levels.append(next_level)
        current_level = next_level

    seconds = time.perf_counter() - start
    return MerkleTreeResult(levels=levels, seconds=seconds)


def read_trusted_root(path: Path) -> str | None:
    """
    Read the root from trusted_merkle_tree.bin if it exists.

    The trusted tree format is level 0 || level 1 || ... || root, and each hash
    is 32 bytes. Therefore the final 32 bytes are the Merkle root.
    """
    if not path.exists():
        return None

    data = path.read_bytes()
    if len(data) < HASH_SIZE or len(data) % HASH_SIZE != 0:
        raise ValueError(f"Invalid trusted Merkle Tree file format: {path}")

    return data[-HASH_SIZE:].hex()


def benchmark(input_path: Path, trusted_tree_path: Path, runs: int) -> Task1Result:
    if runs < 1:
        raise ValueError("runs must be at least 1")

    validate_input_file(input_path)

    single_results = [compute_single_hash(input_path) for _ in range(runs)]
    first_single_hash = single_results[0].hex_digest
    if any(result.hex_digest != first_single_hash for result in single_results):
        raise RuntimeError("Single hash changed between runs; input file may be unstable.")

    merkle_results = [build_merkle_tree(input_path) for _ in range(runs)]
    first_merkle = merkle_results[0]
    if any(result.root_hex != first_merkle.root_hex for result in merkle_results):
        raise RuntimeError("Merkle root changed between runs; input file may be unstable.")

    expected_height = int(math.log2(NUM_BLOCKS))
    if first_merkle.leaf_count != NUM_BLOCKS or first_merkle.height != expected_height:
        raise RuntimeError("Merkle Tree shape does not match the Task 1 specification.")

    trusted_root = read_trusted_root(trusted_tree_path)

    return Task1Result(
        single_hash=first_single_hash,
        single_hash_times=BenchmarkStats([result.seconds for result in single_results]),
        merkle_root=first_merkle.root_hex,
        merkle_times=BenchmarkStats([result.seconds for result in merkle_results]),
        leaf_count=first_merkle.leaf_count,
        height=first_merkle.height,
        internal_node_count=first_merkle.internal_node_count,
        internal_memory_bytes=first_merkle.internal_node_memory_bytes,
        total_node_count=first_merkle.total_node_count,
        total_tree_storage_bytes=first_merkle.total_tree_storage_bytes,
        proof_size_bytes=first_merkle.proof_size_bytes,
        trusted_root=trusted_root,
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_timing_stats(label: str, stats: BenchmarkStats, runs: int) -> None:
    if runs == 1:
        print(f"{label:<22}: {format_time(stats.mean)}")
        return

    print(f"{label:<22}: {format_time(stats.mean)} average over {runs} runs")
    print(f"{'Best time':<22}: {format_time(stats.best)}")
    print(f"{'Worst time':<22}: {format_time(stats.worst)}")
    print(f"{'Std. dev.':<22}: {format_time(stats.stdev)}")


def print_report(input_path: Path, trusted_tree_path: Path, runs: int, result: Task1Result) -> None:
    print("=" * 78)
    print("Project 2 - Task 1: Single Hash vs. Merkle Tree")
    print("=" * 78)
    print(f"Input file            : {input_path}")
    print(f"File size             : {TOTAL_SIZE:,} bytes ({format_bytes(TOTAL_SIZE)})")
    print(f"Block count           : {NUM_BLOCKS} (= 2^{result.height})")
    print(f"Block size            : {BLOCK_SIZE:,} bytes ({format_bytes(BLOCK_SIZE)})")
    print(f"Hash function         : SHA-256 ({HASH_SIZE} bytes per digest)")
    print(f"Benchmark runs        : {runs}")
    print()

    print("[1] Single Hash Result")
    print(f"SHA-256               : {result.single_hash}")
    print_timing_stats("Single hash time", result.single_hash_times, runs)
    print()

    print("[2] Merkle Tree Result")
    print(f"Merkle root           : {result.merkle_root}")
    print_timing_stats("Merkle build time", result.merkle_times, runs)
    print(f"Tree height           : {result.height}")
    print(f"Leaf nodes            : {result.leaf_count}")
    print(f"Internal nodes        : {result.internal_node_count}")
    print(f"Internal overhead     : {result.internal_memory_bytes:,} bytes ({format_bytes(result.internal_memory_bytes)})")
    print(f"Total nodes stored    : {result.total_node_count}")
    print(f"Total hash storage    : {result.total_tree_storage_bytes:,} bytes ({format_bytes(result.total_tree_storage_bytes)})")
    print(f"Future proof size     : {result.proof_size_bytes:,} bytes ({result.height} sibling hashes)")
    print()

    print("[3] Trusted Tree Verification")
    if result.trusted_root is None:
        print(f"Trusted tree file     : {trusted_tree_path} (not found, skipped)")
    else:
        print(f"Trusted tree file     : {trusted_tree_path}")
        print(f"Trusted Merkle root   : {result.trusted_root}")
        print(f"Root match            : {'YES' if result.trusted_root == result.merkle_root else 'NO'}")
    print()

    print("[4] Baseline Interpretation")
    print(f"Single hash detects corruption only after scanning all {format_bytes(TOTAL_SIZE)}.")
    print(
        "The Merkle Tree has a slightly higher initial build cost and stores "
        f"{format_bytes(result.internal_memory_bytes)} of internal nodes."
    )
    print(
        "That overhead enables later O(log2 n) operations: for n = 128 blocks, "
        f"only {result.height} levels are needed for localization or path updates."
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Project 2 Task 1: compare whole-file SHA-256 with a Merkle Tree."
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        default=DEFAULT_INPUT_FILE,
        help=f"Input binary file (default: {DEFAULT_INPUT_FILE})",
    )
    parser.add_argument(
        "--trusted-tree",
        default=DEFAULT_TRUSTED_TREE_FILE,
        help=f"Optional trusted Merkle Tree file for root verification (default: {DEFAULT_TRUSTED_TREE_FILE})",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS,
        help=f"Number of benchmark runs used for timing stability (default: {DEFAULT_RUNS})",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input_file)
    trusted_tree_path = Path(args.trusted_tree)
    result = benchmark(input_path, trusted_tree_path, args.runs)
    print_report(input_path, trusted_tree_path, args.runs, result)


if __name__ == "__main__":
    main()
