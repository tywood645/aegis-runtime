# Security Policy

## Supported Versions

AEGIS is in active early development (pre-1.0). Only the latest commit on the `main` branch is supported with security fixes.

| Branch / Version | Supported          |
| ---------------- | ------------------ |
| `main` (latest)  | :white_check_mark: |
| Older commits    | :x:                |

Once AEGIS reaches a stable release cadence, this table will be updated to reflect supported version lines.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

AEGIS is a security-critical runtime designed to isolate AI agents. Vulnerabilities in AEGIS could directly compromise the systems it is meant to protect, so responsible disclosure is essential.

### How to Report

1. **GitHub Security Advisories (preferred):** Go to [Security → Advisories](https://github.com/tywood645/aegis-runtime/security/advisories) and click **"Report a vulnerability."** This creates an encrypted, private channel.

2. **Email:** Send a detailed report to **tywood645@gmail.com** with the subject line: `[SECURITY] aegis-runtime — <brief description>`

### What to Include

- A clear description of the vulnerability and its potential impact
- Steps to reproduce, including relevant Agent Definition Spec (TOML) configs if applicable
- The component affected (e.g., policy engine, audit log, daemon, spec parser)
- Affected commit hash or version
- Suggested fix or mitigation, if any

### Response Timeline

| Stage              | Target        |
| ------------------ | ------------- |
| Acknowledgment     | 72 hours      |
| Initial assessment | 7 days        |
| Patch or mitigation| 30 days       |

Credit will be given to reporters unless anonymity is requested.

## Disclosure Policy

This project follows **coordinated disclosure**. Please allow up to 90 days for a fix before public disclosure. If a fix is released sooner, disclosure may proceed at that point.

## Scope

### In Scope

These are the areas where vulnerabilities have the highest impact:

- **Policy engine bypasses** — an agent gaining read, write, or execute access outside its defined permissions
- **Sandbox escapes** — breaking out of filesystem, namespace, or network isolation
- **Audit log tampering** — modifying, truncating, or forging entries without detection (breaking the SHA-256 hash chain)
- **Privilege escalation** — an agent or unprivileged process gaining elevated access through the daemon
- **Daemon socket exploitation** — unauthorized commands or injection via the Unix socket interface
- **Agent Definition Spec parsing flaws** — malformed TOML configs that bypass validation or cause unsafe behavior
- **Credential vault exposure** — leaking secrets across agent boundaries (once implemented)
- **Dependency vulnerabilities** — exploitable flaws in Rust crates used by AEGIS with a demonstrated attack path

### Out of Scope

- Denial of service against a self-hosted daemon instance
- Theoretical issues without a proof of concept
- Social engineering
- Vulnerabilities in upstream dependencies without a demonstrated impact on AEGIS
- Issues that require pre-existing root access on the host

## Security Design Principles

AEGIS is built on the following assumptions. Vulnerabilities that violate these are high priority:

1. **Deny by default** — agents have no access unless explicitly granted in their definition spec
2. **Deny overrides allow** — explicit deny rules always take precedence
3. **Agents are untrusted** — the runtime assumes agents will attempt to exceed their permissions
4. **Audit integrity is non-negotiable** — the hash-chained log must detect any tampering
5. **Policy is enforced by the runtime, not by the agent** — agents cannot modify their own constraints
