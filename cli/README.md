# tanod CLI

Native Go command-line client for tanod.

The CLI talks to the non-interactive `tanod-core` `/v1/*` API surface. It cannot use browser OAuth/OIDC; configure `TANOD_API_KEY` when `tanod-core` is exposed beyond loopback.

## Build

```bash
cd cli
go build -o ../bin/tanod ./cmd/tanod
```

## Use

```bash
export TANOD_URL=http://127.0.0.1:8787
export TANOD_API_KEY=dev-key # required for non-loopback tanod-core APIs

./bin/tanod help
./bin/tanod decide ../examples/requests/shell-write-prod.json
./bin/tanod request-approval ../examples/requests/shell-write-prod.json --by ross@example.com
./bin/tanod approvals --status pending
```
