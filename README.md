# agentsh + Deno Sandbox

Runtime security governance for AI agents using [agentsh](https://github.com/canyonroad/agentsh) v0.16.6 with [Deno Deploy Sandboxes](https://deno.com/deploy/sandboxes) (Firecracker microVMs).

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

## Security Capabilities in Deno Sandbox

`agentsh detect` output inside a Deno Sandbox (Firecracker microVM, Debian Trixie, agentsh v0.16.6):

```
Platform: linux
Security Mode: landlock-only
Protection Score: 80%

CAPABILITIES
----------------------------------------
  capabilities_drop        YES
  cgroups_v2               YES
  ebpf                     YES
  file_enforcement         landlock
  fuse                     -
  landlock                 YES
  landlock_abi             YES (v2)
  landlock_network         -
  pid_namespace            -
  ptrace                   YES
  seccomp                  YES
  seccomp_basic            YES
  seccomp_user_notify      YES
```

### Why the 80% score doesn't reflect actual enforcement

The `detect` command reports kernel capabilities, not what's configured. The 80% score reflects missing kernel features (FUSE, Landlock network, PID namespace), but with ptrace+seccomp enabled in `config.yaml`, **all four policy dimensions are kernel-enforced**:

| Policy Dimension | Enforcement Mechanism | Status |
|---|---|---|
| **Command policy** | Shell shim + seccomp | Enforced |
| **File policy** | ptrace + seccomp prefilter | Enforced |
| **Network policy** | eBPF + seccomp | Enforced |
| **Env var policy** | exec API + BASH_ENV injection | Enforced |

### How file policy enforcement works

Firecracker microVMs don't expose `/dev/fuse` or mount Landlock's securityfs, so neither FUSE nor Landlock can enforce `file_rules`. Instead, agentsh v0.16.6 uses **ptrace with seccomp prefiltering**:

1. **ptrace** attaches to every child process spawned via the exec API
2. A **seccomp BPF prefilter** (`SECCOMP_RET_TRACE`) is injected into each tracee, so only file/exec/network syscalls trigger ptrace stops -- all other syscalls pass through at kernel speed
3. On each file syscall (`openat`, `unlinkat`, `renameat2`, `mkdirat`, etc.), ptrace **freezes the thread**, reads the path from the stopped process's memory, evaluates it against `file_rules`, and allows or denies with `EACCES`
4. Because the thread is frozen during evaluation, there is **no TOCTOU (time-of-check/time-of-use) race** -- unlike seccomp `SECCOMP_USER_NOTIF_FLAG_CONTINUE` where another thread could modify the path between check and use

### Capability comparison

| Capability | Local (bare metal) | Deno Sandbox | Notes |
|---|---|---|---|
| Security Mode | full | landlock-only | Detect reports kernel features, not configured enforcement |
| Protection Score | 100% | 80% | Functional enforcement is equivalent (see above) |
| eBPF | yes | yes | Provides network filtering |
| Seccomp (user_notify) | yes | yes | Powers shell shim + command interception |
| Landlock | v5 | detected v2 | Not enforcing (securityfs not mounted); ptrace compensates |
| Landlock network | yes | no | eBPF provides equivalent filtering |
| FUSE | yes | no | No /dev/fuse; ptrace compensates |
| ptrace | yes | yes | File policy enforcement + seccomp prefilter |
| real_paths | yes | yes | Command interception via binary renaming |
| BASH_ENV | yes | yes | Shell startup hook injection |
| PID namespace | no | no | Redundant in microVM |
| File policy enforcement | yes | **yes** | Via ptrace + seccomp prefilter |
| Command policy enforcement | yes | yes | Via shell shim + seccomp + real_paths |
| Network policy enforcement | yes | yes | Via eBPF + seccomp |
| Env var policy enforcement | yes | yes | Via exec API + BASH_ENV |

## Capabilities on Deno Sandboxes

| Capability | Status | Notes |
|------------|--------|-------|
| ptrace | Working | Syscall-level enforcement: execve, file, network, signal interception |
| seccomp | Working | Command interception via `seccomp_user_notify` |
| seccomp prefilter | Working | BPF pre-filter injected into tracees, reduces ptrace overhead |
| eBPF | Working | Network filtering (private CIDRs, metadata endpoints) |
| Network proxy | Working | Domain/IP/port filtering via agentsh proxy |
| DLP | Working | Secret detection and redaction in LLM traffic |
| Audit logging | Working | All operations logged |
| BASH_ENV | Working | Shell startup hook injection for builtin interception |
| Landlock | Detected, not enforcing | Kernel 6.1 has Landlock v2 but `/sys/kernel/security/landlock/` not mounted |
| FUSE | Not available | `/dev/fuse` not exposed in Firecracker VM |
| cgroups v2 | Detected | Available but read-only |
| PID namespace | Not available | Not available in Firecracker config |

## For Deno Engineers: What to Enable

**Note**: All core security enforcement works today using ptrace + seccomp. ptrace intercepts syscalls (execve, file I/O, network, signals) and enforces policy rules. The seccomp BPF prefilter ensures only traced syscalls trigger ptrace stops for minimal overhead. Together they provide **full policy enforcement across commands, files, network, and environment variables** with no Deno-side changes needed.

The features below are optional enhancements, not requirements.

### Landlock (`/sys/kernel/security/landlock/`) -- Medium Impact

**Current state**: The Firecracker kernel (6.1) has Landlock v2 compiled in, and agentsh detects it. But `/sys/kernel/security/landlock/` is not mounted inside the VM, so Landlock rules cannot be applied. agentsh degrades silently and uses ptrace for file enforcement instead.

**What it would add** (beyond what ptrace already enforces):
- **Kernel-native file policy** -- Landlock is an LSM (Linux Security Module) that enforces file access rules directly in the kernel, with zero userspace overhead per syscall. It's faster than ptrace for file enforcement.
- **Reduced ptrace scope** -- with Landlock handling file policy, ptrace could be limited to exec and network interception, reducing the number of ptrace stops.

**Not needed for**: File enforcement works today via ptrace. Landlock would be a performance optimization, not a functional gap.

**How to enable**: Mount securityfs inside the Firecracker VM guest:
```
mount -t securityfs securityfs /sys/kernel/security
```
This requires either a guest init script change or exposing the mount in the Firecracker VM template. The kernel already has Landlock compiled in -- it just needs the securityfs mount point.

### FUSE (`/dev/fuse`) -- Nice to Have

**Current state**: `/dev/fuse` is not exposed in the Firecracker VM. agentsh uses `real_paths` mode (binary renaming + shims) for command interception, and ptrace for file policy enforcement.

**What it would add** (beyond what ptrace + real_paths already enforce):
- **Soft-delete quarantine** -- `rm` moves files to a quarantine directory instead of deleting. Files can be restored with `agentsh trash restore`. Without FUSE, deletes are blocked or permanent -- there is no undo.
- **VFS-level overlay** -- Interception at the filesystem layer rather than the syscall layer. More resilient against edge cases like direct file descriptor manipulation.

**Not needed for**: File read/write blocking (ptrace handles this), credential file protection, command interception (real_paths handles this).

**How to enable**: Expose `/dev/fuse` (character device 10,229) in the Firecracker VM. Requires the FUSE kernel module and device node. Standard Firecracker configuration -- other platforms (E2B, Daytona) expose it by default.

### Landlock Network (kernel 6.7+) -- Low Impact

**Current state**: The Firecracker kernel is 6.1, which predates Landlock network support (added in 6.7, ABI v4). Network filtering is handled by eBPF instead.

**What it would add**:
- **Kernel-native network policy** -- Landlock v4 can restrict `connect()` and `bind()` by port. Currently eBPF provides equivalent filtering.

**Not needed for**: Network enforcement works today via eBPF + seccomp.

**How to enable**: Upgrade the Firecracker guest kernel to 6.7+.

### PID Namespace -- Low Impact

**Current state**: PID namespace creation is not available.

**What it would add**:
- **Process isolation** -- agentsh can create sessions in isolated PID namespaces, preventing agents from seeing or signaling other processes.

**How to enable**: Allow `CLONE_NEWPID` in the Firecracker configuration or seccomp filter.

### Summary

| Feature | Impact | Current | What's Needed |
|---------|--------|---------|---------------|
| Landlock (securityfs) | Medium -- kernel-native file policy, faster than ptrace | Detected but not enforcing | Mount securityfs in VM guest |
| FUSE | Nice to have -- adds soft-delete quarantine, VFS overlay | Not available | Expose `/dev/fuse` in VM |
| Landlock network | Low -- kernel network policy | Not available (kernel 6.1) | Upgrade kernel to 6.7+ |
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

agentsh v0.16.6 uses `real_paths` mode as an alternative to FUSE in Firecracker (where `/dev/fuse` is unavailable). This renames original binaries (e.g., `/bin/bash` -> `/bin/bash.real`) and installs shims for transparent command interception.

### v0.16.6 features

- **ptrace + seccomp file enforcement** -- kernel-level file policy enforcement without FUSE or Landlock. Uses ptrace to intercept file syscalls with seccomp BPF prefiltering for performance. TOCTOU-safe (thread is frozen during policy evaluation).
- **`real_paths` mode** -- alternative to FUSE for transparent command interception. Renames original binaries and installs shims. Works in Firecracker where `/dev/fuse` is unavailable.
- **`BASH_ENV` injection** -- sets `BASH_ENV=/usr/lib/agentsh/bash_startup.sh` so agentsh hooks into every bash session automatically. Works in both seccomp and ptrace modes.
- **Seccomp prefilter injection** -- when ptrace is enabled, agentsh injects a seccomp BPF filter into each tracee so only traced syscalls (file, exec, network) trigger ptrace stops. Non-traced syscalls pass through at kernel speed.
- **Version pinning** -- install script pins to a specific agentsh version (default: 0.16.6) instead of fetching `latest` from the GitHub API, removing the `jq` dependency.

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
- [agentsh + Daytona](https://github.com/canyonroad/agentsh-daytona) -- agentsh integration with Daytona sandboxes
- [agentsh + Cloudflare](https://github.com/canyonroad/agentsh-cloudflare) -- agentsh integration with Cloudflare Containers
- [Deno Deploy Sandboxes](https://deno.com/deploy/sandboxes) -- Firecracker microVM sandbox platform

## License

MIT
