# ads-audit

The journal. It consumes decisions from RabbitMQ and writes them to PostgreSQL, and it
answers what they add up to. Nothing writes to it over HTTP: the only way in is the
queue, and the only way out is a read.

Every service that decides or enforces publishes here, so the journal is the one place
where the whole history of what an agent asked for exists.

## What is recorded

Decisions with their arguments: who, when, which capability, which resource, the
verdict, the rule that produced it, and the hash of the policy version it was made
under. Paths, commands and migration filenames are included — without them the budget
cannot tell a stray mistake from a search for a way around.

Prompts, model answers and diffs are not recorded unless explicitly opted in per event.

## Append-only

There is no way to remove a row. The repository protocol has `append` and two reads and
nothing else; retention is meant to be a dropped partition, not a `DELETE`. The table is
`PARTITION BY RANGE (recorded_at)` with monthly partitions, extended by a background
task so a row always has somewhere to land.

Dropping old partitions is not implemented here — that is an operator procedure, and so
is the database role that physically lacks `DELETE`.

## Redelivery

RabbitMQ delivers at least once, so every event carries an `event_id` and a
`recorded_at` fixed when the decision was made rather than when the row lands. The
unique index is keyed on both, and a second delivery of the same event is a no-op. This
matters beyond tidiness: the budget charges a repeated denial a multiple of the first,
so a duplicate row would look like an agent trying again.

A message is acknowledged only after the write commits. A crash in between replays it.
A body that cannot be decoded at all is rejected without requeue, because replaying it
forever would block everything behind it.

## API

`/audit` requires `Authorization: Bearer $ADS_AUDIT_API_TOKEN`; health is public.

| | |
|---|---|
| `GET /audit/runs/{run_id}/budget` | the accumulated cost of denials within one run |
| `GET /audit/subjects/{subject}/budget` | the same across a subject's runs |
| `GET /health/live` | the process is up |
| `GET /health/ready` | the journal answers. 503 otherwise |

The budget is derived from the journal on every read, never stored as a counter, so it
cannot drift away from the events it summarises. Accumulation per subject is a signal
for whoever reviews the journal, not an automatic block: blocking a person for what an
agent did is a guaranteed argument.

## Configuration

Required:

- `ADS_AUDIT_API_TOKEN` — at least 16 characters
- `ADS_AMQP_URL`, `ADS_DATABASE_URL` (`postgresql+asyncpg://…`)
- `ADS_TLS_CERT_PATH`, `ADS_TLS_KEY_PATH`

Optional: `ADS_TLS_CA_BUNDLE`, `ADS_BIND_HOST` (`0.0.0.0`), `ADS_PORT` (`8080`),
`ADS_AUDIT_PREFETCH` (`100`), `ADS_AUDIT_PARTITIONS_AHEAD` (`2`).

## Not built yet

Who reads the journal, and on what trigger, is not decided — and until it is, the
deny-rate and capability distribution it can already produce have no audience. A high
deny rate means either a poor agent, or a policy that is too narrow, or a capability
missing for the task, and telling those apart needs a process, not a table.
