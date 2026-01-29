# agentsh + Deno Sandbox

Run AI agents inside [Deno Deploy Sandboxes](https://deno.com/deploy/sandboxes) with [agentsh](https://www.agentsh.org) security policy enforcement.

agentsh provides default-deny allowlists for file, network, process, and signal operations. Deno Sandboxes provide ephemeral Firecracker microVMs. Together, they give AI agents an isolated, policy-enforced execution environment.

## What this adds to Deno Sandbox

A bare Deno Sandbox is a Linux microVM with no security policy layer. This integration adds:

- **Command policy enforcement** -- allowlist of permitted commands; blocks privilege escalation (`sudo`, `su`, `chroot`), network tools (`ssh`, `nc`), system commands (`kill`, `shutdown`, `systemctl`), and recursive deletes (`rm -rf`)
- **Network policy enforcement** -- blocks cloud metadata endpoints (169.254.169.254), private network CIDRs (10.x, 172.16.x, 192.168.x); allows localhost and package registries
- **Environment variable policy** -- allowlist of visible env vars; secrets (AWS_*, OPENAI_API_KEY, DATABASE_URL, etc.) hidden from commands even if set in the server environment; enumeration filtered to prevent credential leakage
- **File operation policy** -- workspace read/write with soft-delete (recoverable), read-only access to system paths, blocked access to credentials and secrets
- **Shell shim** -- transparent interception of all bash invocations through agentsh for policy enforcement
- **Audit logging** -- all operations logged for review
- **DLP redaction** -- sensitive patterns (API keys, tokens) redacted in output

## Security capabilities

`agentsh detect` output inside a Deno Sandbox (Firecracker microVM, Debian Trixie):

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

The 80% score reflects missing kernel features, but **the actual security posture is stronger** because:

| Missing Feature | Why It Doesn't Matter |
|-----------------|----------------------|
| **Landlock network** | eBPF is available and more powerful — agentsh uses it for network filtering. The demos prove private IPs and metadata endpoints are blocked. |
| **PID namespace** | Redundant in a Firecracker microVM. The VM boundary already isolates processes — there are no "other processes" to hide from. The VM is ephemeral and destroyed after use. |
| **FUSE** | The only truly missing feature. Enables filesystem virtualization for transparent file interception. Workaround: Landlock v2 still enforces path-based file access rules. |

The Firecracker microVM itself provides isolation that makes some agentsh features redundant:

```
┌─────────────────────────────────────┐
│  Firecracker microVM (isolation)    │  ← VM boundary
│  ┌───────────────────────────────┐  │
│  │  agentsh (policy enforcement) │  │  ← Policy layer
│  │  ┌─────────────────────────┐  │  │
│  │  │  Your sandboxed code    │  │  │
│  │  └─────────────────────────┘  │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

**What's working:** Seccomp, eBPF, Landlock (v2), cgroups v2, capability dropping — all the enforcement mechanisms needed for command, network, file, and environment policy.

### Capability comparison

| Capability | Local (bare metal) | Deno Sandbox | Notes |
|---|---|---|---|
| Security Mode | full | landlock-only | |
| Protection Score | 100% | 80% | See above — actual security is better |
| eBPF | yes | yes | Covers for missing Landlock network |
| Seccomp (user_notify) | yes | yes | |
| Landlock | v5 | v2 | v2 sufficient for file access control |
| Landlock network | yes | no | eBPF provides equivalent filtering |
| FUSE | yes | no | Only meaningful missing feature |
| PID namespace | no | no | Redundant in microVM |

## Prerequisites

- [Deno](https://deno.land/) 2.x
- A `DENO_DEPLOY_TOKEN` (get one from [Deno Deploy](https://dash.deno.com))

## Setup

```bash
git clone <repo-url>
cd agentsh-deno

# Add your Deno Deploy token
echo "DENO_DEPLOY_TOKEN=your_token_here" > .env
```

## Usage

### Bootstrap a sandbox with agentsh

```typescript
import { createAgentshSandbox } from "./setup.ts";

const sandbox = await createAgentshSandbox();
// sandbox now has agentsh installed, server running, shell shim active

// Run commands through the policy-enforced shell
const output = await sandbox.sh`echo hello`.text();

// Clean up
await sandbox.close();
```

The bootstrap sequence:
1. Creates a Deno Sandbox (Firecracker microVM)
2. Installs system dependencies (curl, jq, libseccomp2, sudo)
3. Downloads and installs agentsh from GitHub releases
4. Creates directories and sets permissions
5. Writes server config and security policy
6. Starts the agentsh server
7. Installs the shell shim (replaces /bin/bash)

### Run the demos

After setup, run any of the demos to see agentsh policy enforcement in action:

```bash
# Command blocking demo -- tests allowed/blocked commands
deno task demo:blocking

# Network policy demo -- tests allowed/blocked network targets
deno task demo:network

# Environment variable policy demo -- tests allowed/hidden env vars
deno task demo:env

# Sandbox verification tests
deno task test

# Run agentsh detect inside a sandbox
deno run --allow-all --env-file=.env detect-sandbox.ts
```

Each demo creates a fresh Deno Sandbox, bootstraps agentsh, runs the tests, and cleans up. Expect ~30-60 seconds for sandbox creation and package installation.

## What the demos test

### demo-blocking.ts

Tests command policy enforcement through agentsh exec:

| Category | Commands | Expected |
|---|---|---|
| Safe commands | `echo`, `pwd`, `ls`, `date`, `python3`, `git` | ALLOWED |
| Privilege escalation | `sudo`, `su`, `chroot` | BLOCKED |
| Network tools | `ssh`, `nc` | BLOCKED |
| System commands | `kill`, `shutdown`, `systemctl` | BLOCKED |
| Recursive delete | `rm -rf`, `rm -r` | BLOCKED |
| Single file delete | `rm file.txt` | ALLOWED |

### demo-network.ts

Tests network policy enforcement:

| Target | Expected |
|---|---|
| Localhost (127.0.0.1:18080) | ALLOWED |
| AWS metadata (169.254.169.254) | BLOCKED |
| Private network (10.0.0.1) | BLOCKED |
| Private network (172.16.0.1) | BLOCKED |
| Private network (192.168.1.1) | BLOCKED |
| npm registry (registry.npmjs.org) | ALLOWED |
| PyPI (pypi.org) | ALLOWED |

### demo-env.ts

Tests environment variable policy enforcement. Injects test secrets into the sandbox environment before starting the agentsh server, then verifies the exec API correctly filters them:

| Env Var | In Policy | Expected |
|---|---|---|
| PATH | allow list | VISIBLE |
| HOME | allow list | VISIBLE |
| TERM | allow list | VISIBLE |
| AWS_SECRET_ACCESS_KEY | deny list | HIDDEN |
| AWS_SESSION_TOKEN | deny list | HIDDEN |
| OPENAI_API_KEY | deny list | HIDDEN |
| DATABASE_URL | deny list | HIDDEN |
| SECRET_SIGNING_KEY | deny list | HIDDEN |
| MY_CUSTOM_SETTING | not listed | HIDDEN |
| `printenv` (all) | block_iteration | filtered (14 vars, no secrets) |
| `env` (all) | block_iteration | filtered (14 vars, no secrets) |

### test-sandbox.ts

Verification smoke tests:

1. agentsh installation -- binary present and reports version
2. Server health -- HTTP health check returns ok
3. Policy file -- default.yaml present in /etc/agentsh/policies/
4. Config file -- config.yaml present in /etc/agentsh/
5. Shell shim -- /bin/bash.real exists (original bash backed up)
6. Command through shim -- echo through /bin/bash works
7. Session creation -- agentsh session create returns valid JSON with id

## Project structure

```
agentsh-deno/
  setup.ts              # Bootstrap function: createAgentshSandbox()
  config.yaml           # agentsh server configuration
  default.yaml          # Security policy (default-deny allowlist)
  demo-blocking.ts      # Command policy demo
  demo-network.ts       # Network policy demo
  demo-env.ts           # Environment variable policy demo
  test-sandbox.ts       # Verification tests
  detect-sandbox.ts     # Run agentsh detect inside sandbox
  deno.json             # Deno project config and tasks
```

## Configuration

### config.yaml

Server configuration: localhost-only binding (127.0.0.1:18080), no auth (sandbox-internal), gRPC on port 9090, full security mode with all enforcement layers enabled.

### default.yaml

Security policy with default-deny allowlist covering:
- **File rules** -- workspace read/write, system read-only, credential blocking
- **Network rules** -- localhost allowed, cloud metadata blocked, private networks blocked, package registries allowed
- **Command rules** -- safe commands allowed, privilege escalation blocked, network tools blocked, system commands blocked, recursive delete blocked
- **Environment policy** -- allowlist (PATH, HOME, TERM, NODE_ENV, GIT_*, etc.), denylist (AWS_*, OPENAI_API_KEY, DATABASE_URL, SECRET_*, etc.), block_iteration prevents full env enumeration
- **Resource limits** -- max file size, process count, open files
- **Audit** -- all operations logged

## License

MIT
