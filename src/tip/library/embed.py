"""Text embeddings for the report library.

Default: BAAI/bge-small-en-v1.5 through fastembed, running locally (ONNX, about 130 MB downloaded once, no API key, no
per-query cost). TIP_EMBEDDER=hash swaps in a tiny deterministic hashing embedder: no download, used by tests.
"""

import hashlib
import os
import re
from functools import lru_cache

import numpy as np

DIMENSIONS = 384
MODEL = "BAAI/bge-small-en-v1.5"


class FastEmbedder:
    def __init__(self) -> None:
        from fastembed import TextEmbedding

        self.model = TextEmbedding(MODEL)

    def embed(self, texts: list[str]) -> list[np.ndarray]:
        return [np.asarray(v, dtype=np.float32) for v in self.model.embed(texts)]


class HashEmbedder:
    """Bag of hashed words, L2-normalised. Captures word overlap only; good enough for tests, not for real search."""

    def embed(self, texts: list[str]) -> list[np.ndarray]:
        out = []
        for text in texts:
            v = np.zeros(DIMENSIONS, dtype=np.float32)
            for word in re.findall(r"[a-z0-9]+", text.lower()):
                v[int(hashlib.md5(word.encode()).hexdigest(), 16) % DIMENSIONS] += 1.0
            norm = np.linalg.norm(v)
            out.append(v / norm if norm else v)
        return out


@lru_cache
def embedder() -> FastEmbedder | HashEmbedder:
    return HashEmbedder() if os.environ.get("TIP_EMBEDDER") == "hash" else FastEmbedder()
