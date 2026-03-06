from pathlib import Path
import subprocess
import json
from typing import List, Any
import numpy as np
import torch
from sentence_transformers import SentenceTransformer

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

def embed(text: str) -> List[float]:
    """Get embedding for a text."""
    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    model = SentenceTransformer("all-MiniLM-L6-v2", device=device)

    emb_text = model.encode(text, convert_to_numpy=True)
    emb_text = emb_text / np.linalg.norm(emb_text)

    return emb_text.tolist()

if __name__ == "__main__":
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

            diff = math.sqrt(sum((a - b) ** 2 for a, b in zip(cand_vec, vec)))
            if diff < 1e-5:
                success += 1
            else:
                print(f"Vector {i}: no exact match found in results")

        print(f"Demo completed. Exact match found for {success}/{N} vectors.")

    elif len(sys.argv) > 1 and sys.argv[1] == "demo2":
        import requests

        device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
        model = SentenceTransformer("all-MiniLM-L6-v2", device=device)

        url = "https://huggingface.co/ngxson/demo_simple_rag_py/resolve/main/cat-facts.txt"

        response = requests.get(url)
        response.encoding = 'utf-8'
        facts = [line.strip() for line in response.text.splitlines() if line.strip()]
        emb_facts = [embed(fact) for fact in facts]

        # print("Inserting fact embeddings...")
        # for i, vec in enumerate(emb_facts):
        #     insert(f"py_vec_{i}", vec)

        # optional second arg: query_fact (string to search for)
        query_fact = sys.argv[2] if len(sys.argv) > 2 else facts[0] # "On average, cats spend 2/3 of every day sleeping. That means a nine-year-old cat has been awake for only three years of its life."
        print(f"Searching for: '{query_fact}'")

        results = query(embed(query_fact), k=10)
        print("Results:")
        for res in results:
            data = res[0]
            score = res[1]
            print(f"Score: {score:.4f} - Fact: {data[:5]}...")  # print first 5 chars of data for brevity

    else:
        print("Usage: python3 crates/semantic-search/python_client.py demo [N]")
