"""CI/image-build only: download tokenizer JSON, never weights or remote Python."""

import argparse
from hashlib import sha256
from pathlib import Path
from urllib.request import urlopen

from ads_context_meter.assets import TOKENIZERS


def bake(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for model_name, asset in TOKENIZERS.items():
        url = f"https://huggingface.co/{asset.repository}/resolve/{asset.revision}/tokenizer.json"
        with urlopen(url, timeout=120) as response:
            content = response.read()
        if sha256(content).hexdigest() != asset.sha256:
            raise RuntimeError(f"tokenizer checksum mismatch: {model_name}")
        (directory / f"{model_name}.json").write_bytes(content)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    bake(parser.parse_args().directory)
