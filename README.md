# Crimson Crawler MCP server

<p align="center">
  <a href="https://crimsoncrawler.com">
    <img src="assets/spider.png" alt="Crimson Crawler spider mark" width="112">
  </a>
</p>
<p align="center">
  <a href="https://crimsoncrawler.com">
    <img src="assets/crimson-crawler-logo.svg" alt="Crimson Crawler" width="520">
  </a>
</p>
<p align="center"><strong>80+ typed threat-intelligence tools for MCP-compatible assistants.</strong></p>
<p align="center">
  <a href="https://crimsoncrawler.com/docs/clients/mcp/">MCP guide</a> ·
  <a href="https://crimsoncrawler.com/dashboard">Get an API key</a> ·
  <a href="server.json">Registry metadata</a>
</p>
<p align="center">
  <img alt="Typed threat-intelligence tools" src="https://img.shields.io/badge/tools-typed-EF4444?style=flat-square&labelColor=18181B">
  <img alt="Streamable HTTP" src="https://img.shields.io/badge/transport-Streamable%20HTTP-EF4444?style=flat-square&labelColor=18181B">
  <img alt="Hosted remote server" src="https://img.shields.io/badge/hosting-remote-EF4444?style=flat-square&labelColor=18181B">
  <a href="LICENSE"><img alt="Apache 2.0" src="https://img.shields.io/badge/license-Apache--2.0-EF4444?style=flat-square&labelColor=18181B"></a>
</p>

Connect an MCP-compatible assistant to Crimson Crawler over Streamable HTTP. Enrich CVEs, work with artifacts and inventories, and generate grounded reports without installing or operating a local server.

## Connect

Use this configuration in clients that accept an `mcpServers` object. Reference the key from your environment so the config file never holds the secret. Claude Code expands `${VAR}` in `.mcp.json`:

```json
{
  "mcpServers": {
    "crimson-crawler": {
      "type": "http",
      "url": "https://crimsoncrawler.com/mcp/v1",
      "headers": {
        "apikey": "${CRIMSON_CRAWLER_API_KEY}"
      }
    }
  }
}
```

VS Code and other clients that interpolate with `${env:...}` read the same variable as:

```json
"headers": {
  "apikey": "${env:CRIMSON_CRAWLER_API_KEY}"
}
```

Set `CRIMSON_CRAWLER_API_KEY` for the process that launches your client, and get an API key from the [Crimson Crawler dashboard](https://crimsoncrawler.com/dashboard). An OS keychain or secret manager is preferred over a shell profile. Never commit a shell profile or client configuration containing the key.

If your client does not interpolate environment variables (Claude Desktop, for example), paste the key as a literal header value. A copyable configuration is available at [`examples/mcp.json`](examples/mcp.json):

```json
"headers": {
  "apikey": "your-api-key-here"
}
```

A literal key lives in the config file itself. Keep the file out of source control and logs, restrict it to its owner with `chmod 600`, and rotate the key if it is ever exposed.

## Data handling

The MCP client sends each selected tool's arguments to the hosted endpoint at `https://crimsoncrawler.com/mcp/v1`. Depending on the tool, that data can include pasted text, uploaded file content, scan results, asset inventories, indicators, and saved-report instructions. The assistant provider may separately receive conversation content under that provider's terms. Crimson Crawler's storage limits, external-model behavior, and retention guidance are documented in [Data & retention](https://crimsoncrawler.com/docs/guides/faq/#data--retention). Review both policies before submitting sensitive or regulated material.

## Status and compatibility

The hosted server and registry metadata declare version `4.1.0`. This repository is a release export rather than the server source; tags and GitHub Releases begin with the first public release.

| Client | Minimum requirement |
|---|---|
| Claude Code | A version that supports remote Streamable HTTP MCP servers and `${VAR}` header interpolation |
| Claude Desktop | A version that supports remote Streamable HTTP MCP servers and custom headers |
| VS Code | A version that supports remote Streamable HTTP MCP servers and `${env:...}` interpolation |
| Other MCP clients | Streamable HTTP transport plus a configurable `apikey` request header |

Client vendors change MCP support independently. Use a current stable client release when a vendor does not publish a durable minimum version for these capabilities.

## Verify the connection

After saving the configuration, restart or reload the client and open its MCP server or tools view. Confirm that `crimson-crawler` connects and lists tools, then invoke one read-only search or enrichment tool with public test data. Do not use sensitive data for the first check.

## What the assistant can do

| Surface | Typical work |
|---|---|
| Enrichment, search, and assessment | Investigate CVEs, products, packages, IOCs, CWEs, ATT&CK techniques, advisories, and proof-of-concept code |
| Artifact workflows | Analyze pasted text and files, then organize artifacts, folders, and saved enrichment reports |
| Inventory workflows | Import and parse scans, prioritize assets, run enrichment, and manage monitoring automations |
| Report Generator | Build citation-backed reports from saved evidence with cite-or-refuse generation |

The [MCP guide](https://crimsoncrawler.com/docs/clients/mcp/) documents the current tool catalog, request fields, response behavior, account limits, and common errors.

## Troubleshooting

- **Authentication failure:** confirm the client process can read `CRIMSON_CRAWLER_API_KEY`, the header name is `apikey`, and the key is active. Restart the client after changing its environment.
- **Rate limit response:** wait for the response's retry window before trying again. Reduce concurrent tool calls if failures recur.
- **Connection failure:** verify the endpoint is exactly `https://crimsoncrawler.com/mcp/v1`, confirm the client supports Streamable HTTP, and check local proxy, DNS, and TLS inspection settings.

## Limitations and known risks

This repository does not contain the hosted server, so it cannot be used for offline or self-hosted execution. Tool calls can transmit sensitive security data to Crimson Crawler and conversation context may also be handled by the MCP client or assistant provider. Tool output can be incomplete or stale when upstream intelligence sources lag, and generated reports require analyst review before operational use. Account limits and rate limits apply.

## See also

- [Quickstart](https://crimsoncrawler.com/docs/quickstart/)
- [Authentication and API keys](https://crimsoncrawler.com/docs/authentication/)
- [Choosing a client surface](https://crimsoncrawler.com/docs/guides/choosing-a-surface/)
- [v1 API reference](https://crimsoncrawler.com/api-reference/v1/)
- [Python SDK](https://crimsoncrawler.com/docs/clients/python-client/)
- [TypeScript SDK](https://crimsoncrawler.com/docs/clients/typescript-client/)
- [CLI](https://crimsoncrawler.com/docs/clients/cli/)

## Registry metadata

[`server.json`](server.json) follows the official MCP Registry schema. It points clients to the hosted endpoint and declares the `apikey` header as required and secret.

## Repository scope

This repository contains public documentation, client configuration, and MCP Registry metadata. It does not contain the hosted server application, deployment files, or private service configuration.

## Security

Report suspected vulnerabilities according to [SECURITY.md](SECURITY.md). Do not include credentials, customer data, or destructive payloads in a public issue.

## License

The repository contents are licensed under the [Apache License 2.0](LICENSE). The license covers these public files, not the hosted server application.

Copyright 2026 Def-Logix, Inc.

See [NOTICE](NOTICE) for the Def-Logix and Crimson Crawler relationship, third-party attribution, and trademark terms.
