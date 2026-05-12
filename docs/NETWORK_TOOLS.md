# Network Tools

`NetworkFetchTool` and `BrowserReadTool` are opt-in adapters for fetching HTTP(S) content. They are not registered in the default tool registry.

Safety properties:

- require the `network` permission
- declare `network_access=True`
- reject non-HTTP(S) URLs
- disallow secrets
- mark fetched content as `untrusted_external`
- mark policy override, credential request, and system instruction use as forbidden

The tool treats external content as evidence or material for summarization only. A fetched page cannot grant permissions, override policy, request credentials, or become a system instruction.

Tests inject a fake fetcher so CI does not depend on external network access.

`BrowserReadTool` additionally extracts a page title, visible text, and links. Script and style content are ignored by the built-in parser.

The kernel blocks network tools by default. Runtime execution requires both policy/approval and explicit construction with `allow_network_tools=True`.
