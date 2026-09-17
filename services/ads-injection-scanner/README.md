# ads-injection-scanner

Reads tool results for prompt injections before they reach a model. ads-guardrail
sends it every string of a result whose rule asks for the `injection` check.

The classifier is HikmaAI's `hikmaai-mdeberta-v3-base-prompt-injection-multilingual`
(Apache 2.0, 11 languages including Russian), its INT8 ONNX build, run with ONNX Runtime
on the CPU. Text longer than the model's window is read in overlapping windows, and a
text scores the highest of its windows.

**The check runs in `review` by default.** On our samples the model finds injections in
English and Russian and stays quiet on ordinary text and code, but it also flags benign
text that merely talks about ignoring something or about instructions (security advice,
`git status --ignored`, a request to an administrator), and it missed an injection hidden
in a Russian code comment. A 10 KB document takes five to seven seconds on eight cores.
Findings go to the journal with no weight and the result is passed on; secrets are
still cut out. See `docs/mcp-tools.md` before enforcing the check.

## API

`POST /scan` requires `Authorization: Bearer $ADS_SCANNER_API_TOKEN`.

```
{"texts": ["...", "..."]}  →  {"verdicts": [{"score": 0.02, "injection": false}, ...]}
```

A scan takes at most 256 texts and a million characters; more is a 413.
`GET /health/live` and `/health/ready` are public.

## The model

The model is baked into the image at `/model` (`ADS_SCANNER_MODEL_DIR`). The build
downloads it from Hugging Face at a pinned revision and checks each file's sha256, so an
image can only ever carry that exact model; the layer comes before the code and stays
cached until the revision changes. Changing the model means changing the revision and
both checksums in the Containerfile, and `MODEL_NOTICE`, which goes into the image next
to the files.

For the chain test with the real model, put the same two files in
`models/injection-classifier/` (ignored by git, outside `services/` so no other image
picks it up):

```
model=https://huggingface.co/HikmaAI/hikmaai-mdeberta-v3-base-prompt-injection-multilingual/resolve/aef60fed9674e497a7ba08e43b41e8666483934e
mkdir -p models/injection-classifier
curl -fL -o models/injection-classifier/model.onnx "$model/onnx/int8/model_quantized.onnx"
curl -fL -o models/injection-classifier/tokenizer.json "$model/tokenizer/tokenizer.json"
```

The service reads label 1 as the injection label, which is how this model is labelled.

## Configuration

Required: `ADS_SCANNER_API_TOKEN` (at least 16 characters), `ADS_SCANNER_MODEL_DIR`,
`ADS_TLS_CERT_PATH`, `ADS_TLS_KEY_PATH`.

Optional: `ADS_SCANNER_THRESHOLD` (`0.5`), `ADS_SCANNER_WINDOW_TOKENS` (`512`),
`ADS_SCANNER_WINDOW_OVERLAP_TOKENS` (`64`), `ADS_BIND_HOST` (`0.0.0.0`), `ADS_PORT`
(`8080`).
