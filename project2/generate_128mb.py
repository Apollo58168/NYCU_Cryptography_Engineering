import numpy as np

# ----------------------------
# Parameters
# ----------------------------
OUTPUT_FILE = "test_128mb.bin"
TOTAL_SIZE = 128 * 1024 * 1024   # 128MB
SEED = 42
CHUNK_SIZE = 1024 * 1024         # 1MB per write

# ----------------------------
# Generate file
# ----------------------------
def generate_binary_file():
    rng = np.random.default_rng(SEED)

    with open(OUTPUT_FILE, "wb") as f:
        bytes_written = 0

        while bytes_written < TOTAL_SIZE:
            remaining = TOTAL_SIZE - bytes_written
            size = min(CHUNK_SIZE, remaining)

            chunk = rng.integers(0, 256, size=size, dtype=np.uint8).tobytes()
            f.write(chunk)

            bytes_written += size

    print(f"File generated: {OUTPUT_FILE}")
    print(f"Size: {TOTAL_SIZE / (1024*1024)} MB")

# ----------------------------
# Run
# ----------------------------
if __name__ == "__main__":
    generate_binary_file()

# 4/16 今天是我生日！祝我生日快樂！(但不會加分;;)