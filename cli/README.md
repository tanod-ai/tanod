# Tanod CLI

Native Go command-line client for Tanod.

## Build

```bash
cd cli
go build -o ../bin/tanod ./cmd/tanod
```

## Use

```bash
export TANOD_URL=http://127.0.0.1:8787
export TANOD_API_KEY=dev-key # only if gateway uses TANOD_API_KEYS

./bin/tanod help
./bin/tanod decide ../examples/requests/shell-write-prod.json
./bin/tanod request-approval ../examples/requests/shell-write-prod.json --by ross@example.com
./bin/tanod approvals --status pending
```
