# Network Security

Network tools are opt-in and are not registered by default.

Default URL safety policy blocks localhost, loopback, private, link-local, metadata, credential-bearing, missing-host, and non-HTTP(S) URLs.

`NetworkFetchTool` and `BrowserReadTool` run URL safety checks during dry-run.

All external content is marked as `untrusted_external` and forbids policy override, credential request, and system instruction use.

Production deployments should still use an egress proxy or network policy enforcement layer. Local URL checks are a guardrail, not a complete network security boundary.
