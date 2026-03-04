from pathlib import Path
import subprocess
import json
from typing import List, Any, Optional

CRATE_DIR = Path(__file__).resolve().parent

def semantic_search_run(args: List[str]) -> subprocess.CompletedProcess:
    cmd = ["./target/debug/cosmian-semantic-search"]
    cmd += args
    return subprocess.run(cmd, capture_output=True)
    # return subprocess.run(cmd, check=True, capture_output=True, text=True)

def insert(data: str, vector: List[float]) -> str:
    """Insert a vector under `data` by calling the Rust CLI.

    Parameters
    - data: identifier to store the vector under.
    - vector: list of floats (length D=384 by default).

    Returns the stdout emitted by the Rust CLI.
    """
    # write vector to a temporary file to avoid very long CLI args
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(vector, f)
        fname = f.name

    proc = semantic_search_run(["insert", "--data", data, "--vector-file", fname])
    try:
        return proc.stdout.strip()
    finally:
        try:
            Path(fname).unlink()
        except Exception:
            pass
    return proc.stdout.strip()


def query(vector: List[float], k: int = 10) -> Any:
    """Query the Rust CLI and return parsed JSON results.

    Parameters
    - vector: list of floats representing the query embedding.
    - k: number of results to request.

    Each returned result is typically an object like
    {"data": <data or null>, "score": <float>, "vector": [...]}.
    """
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(vector, f)
        fname = f.name

    proc = semantic_search_run(["query", "--vector-file", fname, "--k", str(k)])

    try:
        out = proc.stdout.strip()
    finally:
        try:
            Path(fname).unlink()
        except Exception:
            pass
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # If the CLI printed extra lines, try to extract the first JSON array found.
        import re

        m = re.search(r"(\[.*\])", out, re.S)
        if m:
            return json.loads(m.group(1))
        raise

if __name__ == "__main__":
    # Quick demo when executed directly
    import sys
    demo_vec = [0.0] * 384
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        # optional second arg: N (number of vectors)
        N = int(sys.argv[2]) if len(sys.argv) > 2 else 100
        print(f"Running demo with N={N} vectors...")
        # generate N random unit vectors (normal distribution) and insert
        import math
        import random

        def random_unit_vector(D=384):
            v = [random.gauss(0, 1) for _ in range(D)]
            norm = math.sqrt(sum(x * x for x in v)) or 1.0
            return [x / norm for x in v]

        vectors = [random_unit_vector() for _ in range(N)]

        print("Inserting vectors...")
        for i, vec in enumerate(vectors):
            insert(f"py_vec_{i}", vec)

        print("Querying and validating...")
        success = 0
        for i, vec in enumerate(vectors):
            res = query(vec, k=10)
            if not res:
                print(f"Vector {i}: no candidates")
                continue
            top = res[0]
            cand_vec = top[0]
            if not cand_vec:
                print(f"Vector {i}: no vector or data returned")
                continue

            import math

            diff = math.sqrt(sum((a - b) ** 2 for a, b in zip(cand_vec, vec)))
            if diff < 1e-5:
                success += 1
            else:
                print(f"Vector {i}: no exact match found in results")

        print(f"Demo completed. Exact match found for {success}/{N} vectors.")

    else:
        print("Usage: python3 crates/semantic-search/python_client.py demo [N]")
