# postkit

Postgres-native identity, configuration, metering, and job queues. Auth, permissions, versioned config, usage tracking, and scheduled tasks - no external services.

## Modules

| Module | Schema | Purpose |
|--------|--------|---------|
| [authz](authz/) | `authz` | Authorization (ReBAC permissions) |
| [authn](authn/) | `authn` | Authentication (users, sessions, tokens) |
| [config](config/) | `config` | Versioned configuration (prompts, flags, secrets) |
| [meter](meter/) | `meter` | Usage metering (quotas, reservations, ledger) |
| [queue](queue/) | `queue` | Job queues (scheduling, retries, dead letters) |

Each module is independent -- use what you need.

## Install

Requires PostgreSQL 14+.

```bash
git clone https://github.com/varunchopra/postkit.git
cd postkit
make build

# Install everything
psql $DATABASE_URL -f dist/postkit.sql

# Or individual modules
psql $DATABASE_URL -f dist/authz.sql
psql $DATABASE_URL -f dist/authn.sql
psql $DATABASE_URL -f dist/config.sql
psql $DATABASE_URL -f dist/meter.sql
psql $DATABASE_URL -f dist/queue.sql
```

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
pip install git+https://github.com/varunchopra/postkit.git#subdirectory=sdk
```

```python
# authz: permission checks
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

# queue: job scheduling
queue.push("email", {"to": "alice@example.com", "subject": "Welcome"})
job = queue.pull("email", worker_id="worker-1")
queue.ack(job["id"])
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
make build   # Build dist/postkit.sql, dist/authz.sql, dist/authn.sql, dist/config.sql, dist/meter.sql, dist/queue.sql
make test    # Run tests
make docs    # Generate API documentation
make clean   # Cleanup
```

## Working with Agents

We've structured the docs and SDK so you can point an agent like Claude Code at [AGENTS.md](AGENTS.md) in this repo and it'll figure out how to set up identity for your app.

_Or_ you can try out [this Claude Code skill](SKILL.md) in your project.

## License

Apache 2.0
