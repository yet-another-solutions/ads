# ads-mcp-probe

A harmless MCP server for checking the governance chain end to end. Its tools do
nothing real; each one exists to trip one check in ads-guardrail and ads-policy.

| tool | what it trips |
|---|---|
| `echo(text)` | nothing; a secret in `text` is refused on the way out |
| `leak()` | a (fake) cloud key in the result, which is redacted |
| `inject()` | a prompt injection in the result, which is withheld |
| `read_file(path)` | `fs.read`, allowed inside the workdir only; nothing is read |
| `run(command)` | `process.exec`, allowed at the `vm` level only; nothing is run |
| `unbound()` | no binding, so it is refused before it gets here |
| `stream(text)` | an event-stream answer when the client accepts one |

It speaks MCP's Streamable HTTP transport at `/mcp`: `POST` for messages, `DELETE`
to end a session, `GET` is refused (the server never writes unasked). Bindings call
it `mcp:<name>`, where `<name>` is its entry in the guardrail's server table.

## Configuration

Required: `ADS_TLS_CERT_PATH`, `ADS_TLS_KEY_PATH`. Optional: `ADS_BIND_HOST`
(`0.0.0.0`), `ADS_PORT` (`8080`).
