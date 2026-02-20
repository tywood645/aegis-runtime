# AEGIS — Agent Execution, Governance, and Isolation System

**Declarative security policies for AI agents, enforced at the OS level.**

AEGIS is the missing link between AI agent frameworks (OpenClaw, CrewAI, LangChain) and production security. Write a single TOML file that declares what your agent can do — filesystem paths, network endpoints, API scopes, executables — and AEGIS enforces it via Linux namespaces, seccomp, and cgroups. Every action is logged to a tamper-evident audit trail.

## Status

**Phase 0 — Proof of Concept.** Core policy engine, audit trail, daemon, and CLI are functional. Linux namespace isolation coming in Phase 1.

## Quick Start

```bash
# Build
cargo build --release

# Validate an agent definition (offline — no daemon needed)
./target/release/aegis validate examples/inbox-manager.toml

# Inspect effective permissions
./target/release/aegis inspect examples/inbox-manager.toml

# Start daemon (Linux only for full functionality)
AEGIS_DIR=/tmp/aegis AEGIS_SOCKET=/tmp/aegis/aegisd.sock ./target/release/aegisd &

# Register and test policy enforcement
aegis --socket /tmp/aegis/aegisd.sock register examples/inbox-manager.toml
aegis --socket /tmp/aegis/aegisd.sock check-fs inbox-manager read /etc/passwd
# → DENY: path '/etc/passwd' matches deny pattern
```

## Architecture

```
TOML Agent Definition → aegisd (Rust daemon) → Linux kernel primitives
                              ↓
                    Policy Engine → Audit Log (SHA-256 hash chain)
                              ↓
              FS Gate | Net Gate | Exec Gate | API Gate
```

## The Gap AEGIS Fills

| Layer | Existing Tools | What's Missing |
|-------|---------------|----------------|
| Sandbox execution | E2B, microsandbox, Daytona | No agent-aware policy |
| App-level governance | AgentBouncr, Mandate, AIM | No OS-level enforcement |
| Vendor guidance | Microsoft, Gartner, MITRE | No tooling |
| **AEGIS** | — | **Unified: OS isolation + agent policy + audit** |

## License

Apache 2.0
