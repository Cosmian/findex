from pathlib import Path
import subprocess
import json
from typing import List, Any, Optional

CRATE_DIR = Path(__file__).resolve().parent

def semantic_search_run(args: List[str]) -> subprocess.CompletedProcess:
    cmd = ["./target/debug/cosmian-semantic-search"]
    cmd += args
    return subprocess.run(cmd, check=True, capture_output=True, text=True)

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


def read_store() -> dict:
    """Read and return the `store.json` from the crate directory as a Python dict.

    Returns an empty dict if the file does not exist. This helper is useful
    when the Rust CLI returns only `data` and the caller needs the stored
    vector for verification.
    """
    p = CRATE_DIR / "store.json"
    if not p.exists():
        return {}
    with p.open("r") as f:
        return json.load(f)


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
            cand_vec = top.get("vector")
            if not cand_vec:
                # try to recover the vector from the persistent store using the returned data
                doc_id = top.get("data")
                if doc_id is None:
                    print(f"Vector {i}: no vector or data returned")
                    continue
                store = read_store()
                cand_vec = store.get(doc_id)
                if cand_vec is None:
                    print(f"Vector {i}: data {doc_id} not found in store")
                    continue
            # compare numerically (L2) with tolerance because of f32/f64 conversions
            import math

            diff = math.sqrt(sum((a - b) ** 2 for a, b in zip(cand_vec, vec)))
            if diff < 1e-5:
                success += 1
            else:
                print(f"Vector {i}: top mismatch (data={top.get('data')}) diff={diff}")

        print(f"Validation: {success}/{N} exact matches at top")
    else:
        print("Usage: python3 crates/semantic-search/python_client.py demo [N]")
