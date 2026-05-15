# Network Security

Network tools are not registered by default. Runtime execution blocks network
tools unless `allow_network_tools=True` is explicitly set.

`URLSafetyPolicy` blocks common SSRF targets by default:

- localhost and loopback addresses
- private IPv4 ranges
- link-local and metadata service addresses such as `169.254.169.254`
- missing hosts
- embedded username/password URLs
- non-HTTP(S) schemes

External content returned by `NetworkFetchTool` and `BrowserReadTool` is always
marked as `UNTRUSTED_EXTERNAL` and includes forbidden uses such as
`policy_override`, `credential_request`, and `system_instruction`.

This policy reduces SSRF risk but does not replace deployment-level egress
controls, DNS pinning, or proxy enforcement for production deployments.
