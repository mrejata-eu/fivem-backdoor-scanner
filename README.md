# FiveM Backdoor Scanner

Read-only static scanner for suspicious FiveM resource scripts, including a known XOR-obfuscated remote JavaScript loader associated with `z1lly.org`.

**No dependencies, no network requests, no JavaScript execution, no file deletion.** Python 3.9+.

## Quick start

```bash
python3 scanner.py /path/to/txData --json /tmp/fivem-scan.json
```

`--show-review` also prints lower-confidence findings. `--max-mb 24` increases the per-file size limit (default 12 MiB). The JSON report includes paths, hashes, indicators and decoded-layer names. It does **not** include source code.

### Exit codes

- `0`: no CRITICAL/HIGH findings
- `1`: at least one HIGH finding
- `2`: at least one CRITICAL finding

## Detection and limitations

The scanner statically detects known loader domains and endpoints, selected markers, remote `eval` patterns and bounded XOR-array/Unicode-escape decoding. It does **not** run resource code. Detection is heuristic: clean software may be flagged and unknown or modified malware may be missed. A marker alone is classified HIGH rather than proof of compromise. Ordinary use of `eval` is not automatically classified HIGH. The scanner does not assess Lua execution semantics or prove that a file is loaded by an active resource.

Known indicators (for defensive detection): `z1lly.org`, `bekJJ`, `bekJJgg`, `bekJJcfxre`. Do not visit or execute remote payloads.

## Incident response

1. Stop affected resources/server if safe to do so.
2. Preserve suspicious files, hashes, timestamps and logs.
3. Restore affected resources from trusted releases or verified backups.
4. Review `fxmanifest.lua`, startup configuration, filesystem write access, credentials and persistence.
5. Rotate potentially exposed credentials and re-scan after remediation.

Do not automatically delete files based on scanner output. File presence does not identify the person or vendor responsible.

## Privacy

All scanning is local. JSON reports may expose internal filesystem paths and URLs; review before sharing publicly. Never upload secrets or entire private resources as public GitHub issues.

## Development

```bash
python3 -m unittest discover -s tests -v
```

Security reports: open a private security advisory or contact maintainers privately. Please provide sanitized indicators and hashes rather than active payloads.

## License

MIT — see [LICENSE](LICENSE).
