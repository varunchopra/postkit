# postkit

[![PyPI](https://img.shields.io/pypi/v/postkit)](https://pypi.org/project/postkit/)

Postgres-native application infrastructure: one SQL install replaces the separate services you would otherwise run for identity, configuration, metering, coordination, and messaging.

## Modules

| Module | Schema | Purpose |
|--------|--------|---------|
| [authz](authz/) | `authz` | Authorization (ReBAC permissions) |
| [authn](authn/) | `authn` | Authentication (users, sessions, tokens) |
| [config](config/) | `config` | Versioned configuration (prompts, flags, secrets) |
| [lease](lease/) | `lease` | TTL leases with fencing tokens (locks, leader election) |
| [memory](memory/) | `memory` | Agent memory (episodes, facts, recall) |
| [meter](meter/) | `meter` | Usage metering (quotas, reservations, ledger) |
| [outbox](outbox/) | `outbox` | Transactional event feed (fan-out, durable cursors) |
| [presence](presence/) | `presence` | Heartbeat liveness (edge detection, alert hooks) |
| [queue](queue/) | `queue` | Job queues (scheduling, retries, dead letters) |

Each module is independent -- use what you need.

## Install

Requires PostgreSQL 14+ built with ICU support (the default in official packages and images). Load the SQL from the latest release:

```bash
curl -fsSL https://github.com/varunchopra/postkit/releases/latest/download/postkit.sql | psql -v ON_ERROR_STOP=1 "$DATABASE_URL"
```

This installs the eight extension-free modules (authn, authz, config, lease, meter, outbox, presence, queue) and works on any stock PostgreSQL server.

The memory module is not part of `postkit.sql`. It requires pgvector, a PostgreSQL extension that adds a vector column type for similarity search, so it ships separately. Install it on a server where pgvector is available:

```bash
curl -fsSL https://github.com/varunchopra/postkit/releases/latest/download/memory.sql | psql -v ON_ERROR_STOP=1 "$DATABASE_URL"
```

Individual modules (`authn.sql`, `authz.sql`, `config.sql`, `lease.sql`, `memory.sql`, `meter.sql`, `outbox.sql`, `presence.sql`, `queue.sql`) are
attached to each [release](https://github.com/varunchopra/postkit/releases). To build from
source instead, see [Development](#development).

To pin a version, install from a specific tag:
`https://github.com/varunchopra/postkit/releases/download/vX.Y.Z/postkit.sql` for the SQL,
`pip install postkit==X.Y.Z` for the SDK.

## Usage

Works with any language or driver:

```python
cursor.execute("SELECT authz.check(%s, %s, %s, %s, %s)", ("user", user_id, "read", "doc", doc_id))
```

```typescript
await pool.query("SELECT authz.check($1, $2, $3, $4, $5)", ["user", userId, "read", "doc", docId]);
```

```go
db.QueryRow(ctx, "SELECT authz.check($1, $2, $3, $4, $5)", "user", userID, "read", "doc", docID).Scan(&ok)
```

## Python SDK

Optional typed client (requires Python 3.10+):

```bash
pip install postkit
```

```python
# authz: permission checks
authz.set_hierarchy("repo", "admin", "write", "read")
authz.grant("admin", resource=("repo", "api"), subject=("user", "alice"))
authz.check(("user", "alice"), "read", ("repo", "api"))  # True

# authn: user management
user_id = authn.create_user("alice@example.com", password_hash)
authn.create_session(user_id, token_hash)

# config: versioned configuration
config.set("prompts/bot", {"template": "You are...", "model": "claude-sonnet-4-20250514"})
config.rollback("prompts/bot")

# meter: usage tracking with reservations
meter.allocate("alice", "llm_call", 10000, "tokens")
res = meter.reserve("alice", "llm_call", 4000, "tokens")
meter.commit(res["reservation_id"], 2347)

# lease: locks and leader election with fencing
got = lease.acquire("scheduler", holder="worker-1")
lease.verify("scheduler", "worker-1", got["fence_token"])  # inside protected tx
lease.release("scheduler", "worker-1", got["fence_token"])

# outbox: transactional event feed
outbox.subscribe("orders", "billing", from_="start")
outbox.emit("orders", "order.created", {"order_id": 42})  # inside your transaction
events = outbox.poll("orders", "billing")

# presence: heartbeat liveness
presence.register("worker-7")
presence.heartbeat("worker-7")            # every 10-60s while running
deaths = presence.sweep()                 # from a cron: who went silent?

# queue: job scheduling
queue.push("email", {"to": "alice@example.com", "subject": "Welcome"})
job = queue.pull("email", worker_id="worker-1")
queue.ack(job["id"])

# memory: durable agent memory (pgvector)
memory.set_dimension(1536)                 # once, after install
memory.record("session-1", "user", "my apartment has hard water", keywords=["water"])
hits = memory.recall(keywords=["water"])
```

See [sdk/](sdk/) for details.

## Examples

| App | Description |
|-----|-------------|
| [postkit-notes](https://github.com/varunchopra/postkit-notes) | Multi-tenant notes app with auth, permissions, teams, and impersonation |

## Documentation

See [docs/](docs/) for full API reference with function signatures, parameters, and examples.

## Development

```bash
make setup   # Start Postgres in Docker
make build   # Build dist/postkit.sql plus one dist/<module>.sql per module
make test    # Run tests
make docs    # Generate API documentation
make clean   # Cleanup
```

## Working with Agents

We've structured the docs and SDK so you can point an agent like Claude Code at [AGENTS.md](AGENTS.md) in this repo and it'll figure out how to set up identity for your app.

_Or_ you can try out [this Claude Code skill](SKILL.md) in your project.

## License

Apache 2.0
