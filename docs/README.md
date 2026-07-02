# postkit Documentation

API reference documentation for postkit modules.

## Modules

- [authn](authn/README.md)
- [authz](authz/README.md)
- [config](config/README.md)
- [lease](lease/README.md)
- [meter](meter/README.md)
- [queue](queue/README.md)

## Generating Documentation

Documentation is auto-generated from source code:

```bash
make docs
```

This extracts documentation from:
- Python SDK: docstrings in `sdk/src/postkit/*/client.py`
- SQL functions: `@function` blocks in `*/src/functions/*.sql`

Do not edit generated files directly. Update the source code instead.
