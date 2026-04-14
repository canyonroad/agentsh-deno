# agentsh + Deno Sandbox

Runtime security governance for AI agents using [agentsh](https://github.com/canyonroad/agentsh) v0.18.0 with [Deno Deploy Sandboxes](https://deno.com/deploy/sandboxes) (Firecracker microVMs).

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
|  |  |  - File I/O enforced (ptrace + seccomp)     |  |  |
|  |  |  - Secrets are redacted from output         |  |  |
|  |  |  - All actions are audited                  |  |  |
|  |  +---------------------------------------------+  |  |
|  +---------------------------------------------------+  |
+---------------------------------------------------------+
```

## What agentsh Adds

| Deno Sandbox Provides | agentsh Adds |
|-----------------------|--------------|
| Firecracker microVM isolation | Command blocking (seccomp + shell shim) |
| Ephemeral compute | File I/O policy enforcement (ptrace + seccomp) |
| API access to sandbox | Domain allowlist/blocklist |
| Network-controlled environment | Cloud metadata blocking |
| | Environment variable filtering |
| | Secret detection and redaction (DLP) |
| | Bash builtin interception (BASH_ENV) |
| | Approval-gated workspace deletes |
| | LLM request auditing |
| | Complete audit logging |

## Security Enforcement

agentsh v0.18.0 uses **ptrace with seccomp prefiltering** to enforce all policy dimensions at the kernel level:

| Policy Dimension | Enforcement Mechanism | What It Does |
|---|---|---|
| **Command policy** | Shell shim + seccomp | Blocks dangerous commands (sudo, ssh, kill, etc.) |
| **File policy** | ptrace + seccomp prefilter | Blocks reads/writes to credential files, system paths; allows workspace |
| **Network policy** | Proxy + DNS proxy | Blocks private CIDRs, cloud metadata endpoints, unauthorized domains |
| **Env var policy** | exec API + BASH_ENV injection | Filters sensitive env vars (AWS keys, tokens); injects shell hooks |

### How ptrace + seccomp file enforcement works

1. **ptrace** attaches to every child process spawned via the exec API
2. A **seccomp BPF prefilter** (`SECCOMP_RET_TRACE`) is injected into each tracee, so only file/exec/network syscalls trigger ptrace stops -- all other syscalls pass through at kernel speed
3. On each file syscall (`openat`, `unlinkat`, `renameat2`, `mkdirat`, etc.), ptrace **freezes the thread**, reads the path from the stopped process's memory, evaluates it against `file_rules`, and allows or denies with `EACCES`
4. Because the thread is frozen during evaluation, there is **no TOCTOU (time-of-check/time-of-use) race**

## Capabilities on Deno Sandboxes

| Capability | Status | Notes |
|------------|--------|-------|
| ptrace | Working | Syscall-level enforcement: execve, file, network, signal interception |
| seccomp | Working | Command interception via `seccomp_user_notify` + `seccomp-execve` |
| seccomp prefilter | Working | BPF pre-filter injected into tracees, reduces ptrace overhead |
| Landlock | Working | Active file protection backend (ABI v2); kernel path restrictions |
| Network proxy | Working | Domain/IP/port filtering via agentsh proxy + DNS proxy |
| DLP | Working | Secret detection and redaction in LLM traffic |
| Audit logging | Working | All operations logged |
| BASH_ENV | Working | Shell startup hook injection for builtin interception |
| Capability drop | Working | Privilege reduction via `capget` + `prctl` |
| FUSE | Not available | `/dev/fuse` not exposed in Firecracker VM |
| eBPF | Not available | Missing `CAP_BPF`; network filtering handled by proxy instead |
| cgroups v2 | Not available | Firecracker VM uses cgroup v1; resource limits unavailable |
| PID namespace | Not available | Not available in Firecracker config |

## For Deno Engineers: What to Enable

**Note**: All core security enforcement works today using Landlock, ptrace, and seccomp. Landlock provides kernel-native file path restrictions. ptrace intercepts syscalls (execve, file I/O, network, signals) and enforces policy rules. The seccomp BPF prefilter ensures only traced syscalls trigger ptrace stops for minimal overhead. Together they provide **full policy enforcement across commands, files, network, and environment variables** with no Deno-side changes needed.

The features below are optional enhancements, not requirements.

### Landlock (`/sys/kernel/security/landlock/`) -- Working

**Current state**: Landlock v2 is the **active file protection backend** in v0.18.0. agentsh uses Landlock for kernel-native path restrictions, with seccomp-notify as a secondary enforcement layer.

**What it provides**:
- **Kernel-native file policy** -- Landlock is an LSM (Linux Security Module) that enforces file access rules directly in the kernel, with zero userspace overhead per syscall.
- **Combined with ptrace** -- ptrace handles exec and network interception, while Landlock handles file path restrictions.

### FUSE (`/dev/fuse`) -- Nice to Have

**Current state**: `/dev/fuse` is not exposed in the Firecracker VM. agentsh uses `real_paths` mode (binary renaming + shims) for command interception, and ptrace for file policy enforcement.

**What it would add** (beyond what ptrace + real_paths already enforce):
- **Soft-delete quarantine** -- `rm` moves files to a quarantine directory instead of deleting. Files can be restored with `agentsh trash restore`. Without FUSE, deletes are blocked or permanent -- there is no undo.
- **VFS-level overlay** -- Interception at the filesystem layer rather than the syscall layer. More resilient against edge cases like direct file descriptor manipulation.

**Not needed for**: File read/write blocking (ptrace handles this), credential file protection, command interception (real_paths handles this).

**How to enable**: Expose `/dev/fuse` (character device 10,229) in the Firecracker VM. Requires the FUSE kernel module and device node. Standard Firecracker configuration -- other platforms (E2B, Daytona) expose it by default.

### Landlock Network (kernel 6.7+) -- Low Impact

**Current state**: The Firecracker kernel is 6.1, which predates Landlock network support (added in 6.7, ABI v4). Network filtering is handled by the agentsh proxy and DNS proxy instead.

**What it would add**:
- **Kernel-native network policy** -- Landlock v4 can restrict `connect()` and `bind()` by port. Currently the agentsh proxy provides equivalent filtering.

**Not needed for**: Network enforcement works today via the agentsh proxy + DNS proxy.

**How to enable**: Upgrade the Firecracker guest kernel to 6.7+.

### PID Namespace -- Low Impact

**Current state**: PID namespace creation is not available.

**What it would add**:
- **Process isolation** -- agentsh can create sessions in isolated PID namespaces, preventing agents from seeing or signaling other processes.

**How to enable**: Allow `CLONE_NEWPID` in the Firecracker configuration or seccomp filter.

### Summary

| Feature | Impact | Current | What's Needed |
|---------|--------|---------|---------------|
| Landlock (securityfs) | N/A -- already working | Active file protection backend (ABI v2) | N/A |
| FUSE | Nice to have -- adds soft-delete quarantine, VFS overlay | Not available | Expose `/dev/fuse` in VM |
| eBPF | Medium -- kernel network monitoring | Not available (missing CAP_BPF) | Run with elevated privileges or grant CAP_BPF |
| Landlock network | Low -- kernel network policy | Not available (kernel 6.1) | Upgrade kernel to 6.7+ |
| cgroups v2 | Low -- resource limits | Not available (cgroup v1) | Enable cgroups v2 in VM |
| PID namespace | Low -- process isolation | Not available | Allow `CLONE_NEWPID` |

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
            |  agentsh server   |  Policy evaluation + ptrace
            |  (auto-started)   |  + seccomp prefilter
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

agentsh v0.18.0 uses `real_paths` mode as an alternative to FUSE in Firecracker (where `/dev/fuse` is unavailable). This renames original binaries (e.g., `/bin/bash` -> `/bin/bash.real`) and installs shims for transparent command interception.

### v0.18.0 features

- **ptrace + seccomp file enforcement** -- kernel-level file policy enforcement without FUSE or Landlock. Uses ptrace to intercept file syscalls with seccomp BPF prefiltering for performance. TOCTOU-safe (thread is frozen during policy evaluation).
- **`real_paths` mode** -- alternative to FUSE for transparent command interception. Renames original binaries and installs shims. Works in Firecracker where `/dev/fuse` is unavailable.
- **`BASH_ENV` injection** -- sets `BASH_ENV=/usr/lib/agentsh/bash_startup.sh` so agentsh hooks into every bash session automatically. Works in both seccomp and ptrace modes.
- **Seccomp prefilter injection** -- when ptrace is enabled, agentsh injects a seccomp BPF filter into each tracee so only traced syscalls (file, exec, network) trigger ptrace stops. Non-traced syscalls pass through at kernel speed.
- **Version pinning** -- install script pins to a specific agentsh version (default: 0.18.0) instead of fetching `latest` from the GitHub API, removing the `jq` dependency.

## Configuration

Security policy is defined in two files:

- **`config.yaml`** -- Server configuration: ptrace tracer, seccomp prefilter, `real_paths` mode, [DLP patterns](https://www.agentsh.org/docs/#llm-proxy), LLM proxy, [env_inject](https://www.agentsh.org/docs/#shell-shim) (BASH_ENV for builtin blocking)
- **`default.yaml`** -- [Policy rules](https://www.agentsh.org/docs/#policy-reference): [command rules](https://www.agentsh.org/docs/#command-rules), [network rules](https://www.agentsh.org/docs/#network-rules), [file rules](https://www.agentsh.org/docs/#file-rules), [environment policy](https://www.agentsh.org/docs/#environment-policy)

See the [agentsh documentation](https://www.agentsh.org/docs/) for the full policy reference.

## Project Structure

```
agentsh-deno/
├── setup.ts              # Bootstrap function: createAgentshSandbox()
├── config.yaml           # Server config (ptrace, seccomp, DLP, network)
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
- **Security diagnostics** -- agentsh detect: seccomp, ptrace, landlock available; capability domains reported
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
- [Deno Deploy Sandboxes](https://deno.com/deploy/sandboxes) -- Firecracker microVM sandbox platform

## License

MIT
