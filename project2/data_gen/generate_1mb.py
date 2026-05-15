import numpy as np

# ----------------------------
# Parameters
# ----------------------------
OUTPUT_FILE = "test_1mb.bin"
BLOCK_SIZE = 1024 * 1024   # 1MB
SEED = 42

# ----------------------------
# Generate block
# ----------------------------
def generate_block():
    rng = np.random.default_rng(SEED)

    data = rng.integers(0, 256, size=BLOCK_SIZE, dtype=np.uint8).tobytes()

    with open(OUTPUT_FILE, "wb") as f:
        f.write(data)

    print(f"Block file generated: {OUTPUT_FILE}")
    print(f"Size: {BLOCK_SIZE} bytes (1MB)")

# ----------------------------
# Run
# ----------------------------
if __name__ == "__main__":
    generate_block()