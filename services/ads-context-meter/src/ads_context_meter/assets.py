"""Immutable build inputs. Runtime never resolves a model name on the network."""

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path


@dataclass(frozen=True)
class TokenizerAsset:
    repository: str
    revision: str
    sha256: str


TOKENIZERS = {
    "glm-5.2": TokenizerAsset(
        "zai-org/GLM-5.2",
        "cf457fa734ab149ffef225f80893eb38c6ff5cdc",
        "19e773648cb4e65de8660ea6365e10acca112d42a854923df93db4a6f333a82d",
    ),
    "glm-5.3": TokenizerAsset(
        "zai-org/GLM-5.3",
        "e0b07fd2751b42d5efa199cc02c2b271deadc516",
        "19e773648cb4e65de8660ea6365e10acca112d42a854923df93db4a6f333a82d",
    ),
}


def read_tokenizer(directory: Path, model_name: str) -> str:
    asset = TOKENIZERS[model_name]
    content = (directory / f"{model_name}.json").read_bytes()
    if sha256(content).hexdigest() != asset.sha256:
        raise RuntimeError(f"tokenizer checksum mismatch: {model_name}")
    return content.decode("utf-8")
