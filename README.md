# Pass to Bitwarden

Run this tool

```bash
go run main.go > pass-export.json
```

Import to Bitwarden

```bash
bw import bitwardenjson pass-export.json
```
