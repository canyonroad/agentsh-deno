# agentsh + Deno Sandbox

Runtime security governance for AI agents using [agentsh](https://github.com/canyonroad/agentsh) v0.15.0 with [Deno Deploy Sandboxes](https://deno.com/deploy/sandboxes) (Firecracker microVMs).

## Why agentsh + Deno Sandbox?

**Deno Sandbox provides isolation. agentsh provides governance.**

Deno Sandboxes give AI agents a secure, isolated compute environment via Firecracker microVMs. But isolation alone doesn't prevent an agent from:

- **Exfiltrating data** to unauthorized endpoints
- **Accessing cloud metadata** (AWS/GCP/Azure credentials at 169.254.169.254)
- **Leaking secrets** in outputs (API keys, tokens, PII)
- **Running dangerous commands** (sudo, ssh, kill, nc)
- **Reaching internal networks** (10.x, 172.16.x, 192.168.x)
- **Deleting workspace files** permanently

agentsh adds the governance layer that controls what agents can do inside the sandbox, providing defense-in-depth:

```
+---------------------------------------------------------+
|  Deno Sandbox / Firecracker microVM (Isolation)         |
|  +---------------------------------------------------+  |
|  |  agentsh (Governance)                             |  |
|  |  +---------------------------------------------+  |  |
|  |  |  AI Agent                                   |  |  |
|  |  |  - Commands are policy-checked              |  |  |
|  |  |  - Network requests are filtered            |  |  |
|  |  |  - File I/O rules defined (real_paths mode) |  |  |
|  |  |  - Secrets are redacted from output         |  |  |
|  |  |  - All actions are audited                  |  |  |
|  |  +---------------------------------------------+  |  |
|  +---------------------------------------------------+  |
+---------------------------------------------------------+
```

## What agentsh Adds

| Deno Sandbox Provides | agentsh Adds |
|-----------------------|--------------|
| Firecracker microVM isolation | Command blocking (seccomp) |
| Ephemeral compute | File I/O policy (real_paths mode) |
| API access to sandbox | Domain allowlist/blocklist |
| Network-controlled environment | Cloud metadata blocking |
| | Environment variable filtering |
| | Secret detection and redaction (DLP) |
| | Bash builtin interception (BASH_ENV) |
| | Landlock execution restrictions |
| | Approval-gated workspace deletes |
| | LLM request auditing |
| | Complete audit logging |

## Security Capabilities in Deno Sandbox

`agentsh detect` output inside a Deno Sandbox (Firecracker microVM, Debian Trixie, agentsh v0.15.0):

```
Platform: linux
Security Mode: landlock-only
Protection Score: 80%

CAPABILITIES
----------------------------------------
  capabilities_drop        YES
  cgroups_v2               YES
  ebpf                     YES
  fuse                     -
  landlock                 YES
  landlock_abi             YES (v2)
  landlock_network         -
  pid_namespace            -
  seccomp                  YES
  seccomp_basic            YES
  seccomp_user_notify      YES
```

### Why 80% is better than it sounds

The 80% score reflects missing kernel features, but **the actual security posture is stronger than a bare sandbox** because of the layered enforcement that IS working:

| Missing Feature | Impact |
|-----------------|--------|
| **Landlock network** | eBPF is available and more powerful -- agentsh uses it for network filtering. The demos prove private IPs and metadata endpoints are blocked. |
| **PID namespace** | Redundant in a Firecracker microVM. The VM boundary already isolates processes. |
| **FUSE** | `/dev/fuse` is not exposed in the sandbox. Means no transparent filesystem virtualization. |

### What's actually enforcing

**Working:**
- **Command policy** -- shell shim intercepts all bash invocations, agentsh applies command_rules (allow/deny/approve)
- **Network policy** -- seccomp + eBPF intercept connect() calls, network_rules block private CIDRs, metadata endpoints, etc.
- **Environment variable policy** -- exec API filters env vars per env_policy allowlist/denylist
- **Session management** -- audit logging, DLP redaction, session lifecycle
- **Seccomp** -- active with user_notify for command interception

**Not enforcing (detected but degraded):**
- **Landlock file policy** -- agentsh detects Landlock v2 as available (kernel 6.1 has it compiled in), but `/sys/kernel/security/landlock/` is not mounted inside the container. With `allow_degraded: true`, agentsh silently degrades. The file_rules in default.yaml (default-deny, workspace read/write, credential blocking) are **not kernel-enforced**. Tested: `/etc/shadow` is readable and writes to `/etc/` succeed through the exec API.
- **FUSE** -- not available (`/dev/fuse` doesn't exist, no kernel module). Would provide filesystem virtualization as an alternative to Landlock for file policy.

This means the `file_rules` section in `default.yaml` defines the **intended** file policy, but it is not currently enforced at the kernel level. Command and network policies ARE enforced.

### What would fix file policy enforcement

Either of these would enable kernel-level file_rules enforcement:

1. **Mount securityfs** -- if the Deno sandbox exposed `/sys/kernel/security/landlock/`, Landlock v2 rules would apply. Requires changes to how Deno provisions sandbox containers.
2. **Expose `/dev/fuse`** -- if FUSE were available, agentsh could virtualize the filesystem. Requires the FUSE kernel module and device node in the container.
3. **Kernel upgrade to 6.7+** -- would additionally enable Landlock network enforcement (currently handled by eBPF).

### Capability comparison

| Capability | Local (bare metal) | Deno Sandbox | Notes |
|---|---|---|---|
| Security Mode | full | landlock-only | |
| Protection Score | 100% | 80% | See above for actual enforcement status |
| eBPF | yes | yes | Provides network filtering |
| Seccomp (user_notify) | yes | yes | Powers shell shim + command interception |
| Landlock | v5 | detected v2 | **Detected but not enforcing** -- securityfs not mounted |
| Landlock network | yes | no | eBPF provides equivalent filtering |
| FUSE | yes | no | No /dev/fuse, no kernel module |
| real_paths | yes | yes | Alternative to FUSE for command interception |
| BASH_ENV | yes | yes | Shell startup hook injection |
| PID namespace | no | no | Redundant in microVM |
| File policy enforcement | yes | **no** | Needs working Landlock or FUSE |
| Command policy enforcement | yes | yes | Via shell shim + seccomp + real_paths |
| Network policy enforcement | yes | yes | Via eBPF + seccomp |
| Env var policy enforcement | yes | yes | Via exec API + BASH_ENV |

## Quick Start

### Prerequisites

- [Deno](https://deno.land/) 2.x
- A `DENO_DEPLOY_TOKEN` (get one from [Deno Deploy](https://dash.deno.com))
- Set environment variables in `.env`:
  ```
  DENO_DEPLOY_TOKEN=your_token_here
  ```

### Build and Test

```bash
git clone https://github.com/canyonroad/agentsh-deno
cd agentsh-deno

# Run the full test suite (38 tests)
deno task test:full

# Run smoke tests (7 tests)
deno task test
```

## How It Works

agentsh replaces `/bin/bash` with a [shell shim](https://www.agentsh.org/docs/#shell-shim) that routes every command through the policy engine:

```
sandbox.sh: /bin/bash -c "sudo whoami"
                     |
                     v
            +-------------------+
            |  Shell Shim       |  /bin/bash -> agentsh-shell-shim
            |  (intercepts)     |
            +--------+----------+
                     |
                     v
            +-------------------+
            |  agentsh server   |  Policy evaluation + seccomp
            |  (auto-started)   |  + real_paths mode
            +--------+----------+
                     |
              +------+------+
              v             v
        +----------+  +----------+
        |  ALLOW   |  |  BLOCK   |
        | exit: 0  |  | exit: 126|
        +----------+  +----------+
```

Every command that Deno Sandbox's `sandbox.sh` executes is automatically intercepted -- no explicit `agentsh exec` calls needed. The bootstrap script (`setup.ts`) installs the shell shim and starts the agentsh server on port 18080.

agentsh v0.15.0 uses `real_paths` mode as an alternative to FUSE in Firecracker (where `/dev/fuse` is unavailable). This renames original binaries (e.g., `/bin/bash` -> `/bin/bash.real`) and installs shims for transparent command interception.

### v0.15.0 features

- **`real_paths` mode** -- alternative to FUSE for transparent command interception. Renames original binaries and installs shims. Works in Firecracker where `/dev/fuse` is unavailable.
- **`BASH_ENV` injection** -- sets `BASH_ENV=/usr/lib/agentsh/bash_startup.sh` so agentsh hooks into every bash session automatically.
- **Improved seccomp** -- enhanced seccomp filters with user_notify for better command interception.
- **Version pinning** -- install script pins to a specific agentsh version (default: 0.15.0) instead of fetching `latest` from the GitHub API, removing the `jq` dependency.

## Configuration

Security policy is defined in two files:

- **`config.yaml`** -- Server configuration: `real_paths` mode, [DLP patterns](https://www.agentsh.org/docs/#llm-proxy), LLM proxy, [seccomp](https://www.agentsh.org/docs/#seccomp), [env_inject](https://www.agentsh.org/docs/#shell-shim) (BASH_ENV for builtin blocking)
- **`default.yaml`** -- [Policy rules](https://www.agentsh.org/docs/#policy-reference): [command rules](https://www.agentsh.org/docs/#command-rules), [network rules](https://www.agentsh.org/docs/#network-rules), [file rules](https://www.agentsh.org/docs/#file-rules), [environment policy](https://www.agentsh.org/docs/#environment-policy)

See the [agentsh documentation](https://www.agentsh.org/docs/) for the full policy reference.

## Project Structure

```
agentsh-deno/
├── setup.ts              # Bootstrap function: createAgentshSandbox()
├── config.yaml           # Server config (real_paths, seccomp, DLP, network)
├── default.yaml          # Security policy (commands, network, files, env)
├── test-template.ts      # Comprehensive test suite (38 tests)
├── test-sandbox.ts       # Smoke tests (7 tests)
├── detect-sandbox.ts     # Security capability diagnostics
├── demo-blocking.ts      # Command and filesystem blocking
├── demo-network.ts       # Network policy blocking
├── demo-env.ts           # Environment variable filtering
└── deno.json             # Deno project config and tasks
```

## Testing

The `test-template.ts` script creates a Deno Sandbox and runs 38 security tests across 10 categories:

- **Installation** -- agentsh binary version check
- **Server & config** -- health check, policy/config files, real_paths enabled, BASH_ENV configured
- **Shell shim** -- shim binary, bash.real preserved, echo through shim
- **Security diagnostics** -- agentsh detect: seccomp, cgroups_v2, landlock, ebpf
- **Command blocking** -- sudo, su, ssh, kill, rm -rf blocked; echo, git allowed
- **Network blocking** -- npmjs.org allowed; metadata, private networks blocked
- **Environment policy** -- sensitive vars filtered, HOME/PATH present, BASH_ENV set, unlisted vars hidden
- **File I/O** -- workspace/tmp writes allowed; system file reads verified
- **Multi-context blocking** -- direct exec API sudo/su/ssh blocked; safe commands via env/find allowed
- **Credential blocking** -- ~/.ssh/id_rsa, ~/.aws/credentials blocked via exec API

```bash
deno task test:full
```

## Related Projects

- [agentsh](https://github.com/canyonroad/agentsh) -- Runtime security for AI agents ([docs](https://www.agentsh.org/docs/))
- [agentsh + E2B](https://github.com/canyonroad/e2b-agentsh) -- agentsh integration with E2B sandboxes
- [Deno Deploy Sandboxes](https://deno.com/deploy/sandboxes) -- Firecracker microVM sandbox platform

## License

MIT
