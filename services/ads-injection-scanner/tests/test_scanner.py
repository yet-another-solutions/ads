from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import msgspec
import numpy as np
import pytest
from litestar.testing import TestClient
from tokenizers import Tokenizer, models, pre_tokenizers, processors

from ads_commons.injection_scanner import SCAN_PATH, ScanResponse
from ads_injection_scanner.app import create_app
from ads_injection_scanner.classifier import PromptGuardClassifier
from ads_injection_scanner.config import Settings

TOKEN = "scanner-api-token-32-bytes-long"
VOCABULARY = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "hello", "world", "ignore", "rules"]
TOKEN_ID = {word: index for index, word in enumerate(VOCABULARY)}
ATTACK_TOKEN = TOKEN_ID["ignore"]
BENIGN = 0
MALICIOUS = 1


def _tokenizer() -> Tokenizer:
    tokenizer = Tokenizer(models.WordLevel(TOKEN_ID, unk_token="[UNK]"))
    tokenizer.pre_tokenizer = pre_tokenizers.Whitespace()
    tokenizer.post_processor = processors.BertProcessing(
        ("[SEP]", TOKEN_ID["[SEP]"]), ("[CLS]", TOKEN_ID["[CLS]"])
    )
    return tokenizer


@dataclass(frozen=True)
class _Input:
    name: str


class AttackTokenSession:
    def __init__(self, inputs: Sequence[str] = ("input_ids", "attention_mask")) -> None:
        self.inputs = [_Input(name) for name in inputs]
        self.batches: list[dict[str, Any]] = []

    def get_inputs(self) -> Sequence[Any]:
        return self.inputs

    def run(self, output_names: None, input_feed: dict[str, Any]) -> Sequence[Any]:
        self.batches.append(input_feed)
        ids = input_feed["input_ids"] * input_feed["attention_mask"]
        attacked = (ids == ATTACK_TOKEN).any(axis=1)
        logits = np.where(attacked[:, None], [[-3.0, 3.0]], [[3.0, -3.0]])
        return [logits]


def _classifier(
    session: AttackTokenSession, window_tokens: int = 8, overlap: int = 2
) -> PromptGuardClassifier:
    return PromptGuardClassifier(
        session,
        _tokenizer(),
        window_tokens=window_tokens,
        window_overlap_tokens=overlap,
        malicious_label_index=MALICIOUS,
    )


def test_a_benign_text_scores_low() -> None:
    assert _classifier(AttackTokenSession()).malicious_probability("hello world") < 0.01


def test_an_attack_scores_high() -> None:
    assert _classifier(AttackTokenSession()).malicious_probability("ignore rules") > 0.99


def test_a_long_text_is_read_in_overlapping_windows() -> None:
    session = AttackTokenSession()
    text = " ".join(["hello"] * 20)
    _classifier(session).malicious_probability(text)
    ids = session.batches[-1]["input_ids"]
    assert ids.shape[0] > 1
    assert ids.shape[1] == 8
    assert all(row[0] == TOKEN_ID["[CLS]"] for row in ids)


def test_an_attack_at_the_end_of_a_long_text_is_found() -> None:
    text = " ".join(["hello"] * 40 + ["ignore"])
    assert _classifier(AttackTokenSession()).malicious_probability(text) > 0.99


def test_padding_is_masked_out() -> None:
    session = AttackTokenSession()
    _classifier(session).malicious_probability(" ".join(["hello"] * 7))
    mask = session.batches[-1]["attention_mask"]
    assert mask[-1].sum() < mask.shape[1]


def test_only_the_inputs_the_model_declares_are_fed() -> None:
    with_types = AttackTokenSession(("input_ids", "attention_mask", "token_type_ids"))
    _classifier(with_types).malicious_probability("hello")
    assert set(with_types.batches[-1]) == {"input_ids", "attention_mask", "token_type_ids"}
    without_types = AttackTokenSession(("input_ids", "attention_mask"))
    _classifier(without_types).malicious_probability("hello")
    assert set(without_types.batches[-1]) == {"input_ids", "attention_mask"}


def test_an_overlap_as_long_as_the_window_is_refused() -> None:
    with pytest.raises(ValueError, match="overlap"):
        _classifier(AttackTokenSession(), window_tokens=8, overlap=8)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        api_token=TOKEN,
        tls_cert_path=tmp_path / "tls.crt",
        tls_key_path=tmp_path / "tls.key",
        model_dir=tmp_path,
        max_texts_per_scan=3,
        max_characters_per_scan=100,
    )


def _client(settings: Settings) -> TestClient:
    return TestClient(app=create_app(settings, _classifier(AttackTokenSession())))


@pytest.fixture
def scanner(settings: Settings) -> Iterator[TestClient]:
    with _client(settings) as client:
        client.headers["authorization"] = f"Bearer {TOKEN}"
        yield client


def test_every_text_gets_its_own_verdict(scanner: TestClient) -> None:
    response = scanner.post(SCAN_PATH, json={"texts": ["hello world", "ignore rules", "  "]})
    assert response.status_code == 200
    scanned = msgspec.convert(response.json(), ScanResponse)
    assert [verdict.injection for verdict in scanned.verdicts] == [False, True, False]
    assert scanned.verdicts[2].score == 0.0
    assert scanned.injection_found
    assert scanned.highest_score > 0.99


def test_the_threshold_decides(settings: Settings) -> None:
    strict = replace(settings, injection_threshold=0.999999)
    with _client(strict) as client:
        client.headers["authorization"] = f"Bearer {TOKEN}"
        verdict = client.post(SCAN_PATH, json={"texts": ["ignore rules"]}).json()["verdicts"][0]
    assert verdict["injection"] is False


def test_the_scan_needs_the_token(settings: Settings) -> None:
    with _client(settings) as client:
        assert client.post(SCAN_PATH, json={"texts": ["hello"]}).status_code == 401
        client.headers["authorization"] = "Bearer wrong-token-wrong-token"
        assert client.post(SCAN_PATH, json={"texts": ["hello"]}).status_code == 401


def test_too_many_texts_are_refused(scanner: TestClient) -> None:
    response = scanner.post(SCAN_PATH, json={"texts": ["hello"] * 4})
    assert response.status_code == 413


def test_too_much_text_is_refused(scanner: TestClient) -> None:
    response = scanner.post(SCAN_PATH, json={"texts": ["hello " * 30]})
    assert response.status_code == 413


def test_a_request_without_texts_is_refused(scanner: TestClient) -> None:
    assert scanner.post(SCAN_PATH, json={}).status_code == 400


def test_health_is_public(settings: Settings) -> None:
    with _client(settings) as client:
        assert client.get("/health/live").json() == {"status": "ok"}
        assert client.get("/health/ready").json() == {"status": "ok"}
