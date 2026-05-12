# Trace Viewer

Leos can render an audit JSONL log as a static HTML trace.

## Run

```bash
leos trace-html logs/latest.jsonl --output trace.html
```

The output is a self-contained HTML file. It shows:

- Event counts.
- Timeline order.
- Event type.
- Message.
- JSON payload.

## Why Static HTML

A static trace viewer is easy to archive, attach to CI artifacts, or share during
incident review. It does not require a server and does not execute untrusted
audit content as script.
