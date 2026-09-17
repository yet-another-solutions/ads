from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol

import numpy as np
import onnxruntime
from tokenizers import Encoding, Tokenizer

MODEL_FILE = "model.onnx"
TOKENIZER_FILE = "tokenizer.json"
MODEL_INPUTS = ("input_ids", "attention_mask", "token_type_ids")


class InjectionClassifier(Protocol):
    def malicious_probability(self, text: str) -> float: ...


class OnnxSession(Protocol):
    def get_inputs(self) -> Sequence[Any]: ...

    def run(self, output_names: None, input_feed: dict[str, Any]) -> Sequence[Any]: ...


class PromptGuardClassifier:
    def __init__(
        self,
        session: OnnxSession,
        tokenizer: Tokenizer,
        *,
        window_tokens: int,
        window_overlap_tokens: int,
        malicious_label_index: int,
    ) -> None:
        text_tokens_per_window = window_tokens - tokenizer.num_special_tokens_to_add(False)
        if window_overlap_tokens >= text_tokens_per_window:
            raise ValueError("the window overlap must be shorter than the text in a window")
        self._session = session
        self._tokenizer = tokenizer
        self._tokenizer.no_padding()
        self._tokenizer.no_truncation()
        self._text_tokens_per_window = text_tokens_per_window
        self._window_overlap_tokens = window_overlap_tokens
        self._input_names = [
            node.name for node in session.get_inputs() if node.name in MODEL_INPUTS
        ]
        self._malicious_label_index = malicious_label_index

    @classmethod
    def from_directory(
        cls,
        model_dir: Path,
        *,
        window_tokens: int,
        window_overlap_tokens: int,
        malicious_label_index: int,
    ) -> PromptGuardClassifier:
        session = onnxruntime.InferenceSession(
            str(model_dir / MODEL_FILE), providers=["CPUExecutionProvider"]
        )
        return cls(
            session,
            Tokenizer.from_file(str(model_dir / TOKENIZER_FILE)),
            window_tokens=window_tokens,
            window_overlap_tokens=window_overlap_tokens,
            malicious_label_index=malicious_label_index,
        )

    def malicious_probability(self, text: str) -> float:
        windows = self._windows_of(text)
        logits = self._session.run(None, self._model_feed(windows))[0]
        probabilities = _softmax(np.asarray(logits, dtype=np.float64))
        return float(probabilities[:, self._malicious_label_index].max())

    def _windows_of(self, text: str) -> list[Encoding]:
        whole_text = self._tokenizer.encode(text, add_special_tokens=False)
        whole_text.truncate(self._text_tokens_per_window, stride=self._window_overlap_tokens)
        windows = [whole_text, *whole_text.overflowing]
        return [self._tokenizer.post_process(window) for window in windows]

    def _model_feed(self, windows: list[Encoding]) -> dict[str, Any]:
        longest = max(len(window.ids) for window in windows)
        shape = (len(windows), longest)
        columns = {
            "input_ids": np.zeros(shape, dtype=np.int64),
            "attention_mask": np.zeros(shape, dtype=np.int64),
            "token_type_ids": np.zeros(shape, dtype=np.int64),
        }
        for row, window in enumerate(windows):
            length = len(window.ids)
            columns["input_ids"][row, :length] = window.ids
            columns["attention_mask"][row, :length] = window.attention_mask
            columns["token_type_ids"][row, :length] = window.type_ids
        return {name: columns[name] for name in self._input_names}


def _softmax(logits: np.ndarray[Any, Any]) -> np.ndarray[Any, Any]:
    shifted = logits - logits.max(axis=1, keepdims=True)
    exponentials = np.exp(shifted)
    result: np.ndarray[Any, Any] = exponentials / exponentials.sum(axis=1, keepdims=True)
    return result
