# Safety Evals

Run:

```bash
leos eval --suite safety
```

The safety suite checks workspace escape, prompt injection from network content, secret exfiltration, policy bypass, rollback reliability, SSRF, high-risk approval, and output schema violations.

The eval command exits non-zero if any case fails.
