# Deno Sandbox + agentsh Integration — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a Deno-based integration that bootstraps agentsh inside Deno Deploy Sandboxes, providing policy-enforced command execution, network control, and audit logging for AI agents — mirroring the existing E2B integration.

**Architecture:** A `setup.ts` module exports `createAgentshSandbox()` which creates a Deno Sandbox, installs agentsh via shell commands (apt-get + dpkg), writes config/policy YAML files, starts the agentsh server, and installs the shell shim. Demo and test scripts validate the integration. Config and policy files are adapted from the E2B version with Deno-specific adjustments.

**Tech Stack:** Deno runtime, `@deno/sandbox` (from JSR), agentsh v0.8.10+, YAML config files

---

## Reference

The E2B integration lives at `/home/eran/work/canyonwork/e2b-agentsh/`. Key patterns to mirror:
- Template installs agentsh from GitHub releases `.deb`
- Config: localhost-only server, no auth, full security mode
- Policy: default-deny allowlist for files, network, commands
- Shell shim transparently intercepts `/bin/bash`
- Demos test command blocking and network blocking

Key difference: E2B has a template build system that pre-bakes images. Deno Sandboxes are ephemeral — we bootstrap at creation time via `sandbox.sh`.

---

### Task 1: Project scaffolding — deno.json and .gitignore

**Files:**
- Create: `deno.json`
- Create: `.gitignore`

**Step 1: Create `deno.json`**

```json
{
  "imports": {
    "@deno/sandbox": "jsr:@deno/sandbox"
  },
  "tasks": {
    "demo:blocking": "deno run --allow-net --allow-env --allow-read demo-blocking.ts",
    "demo:network": "deno run --allow-net --allow-env --allow-read demo-network.ts",
    "test": "deno run --allow-net --allow-env --allow-read test-sandbox.ts"
  }
}
```

**Step 2: Create `.gitignore`**

```
.env
node_modules/
.claude/
```

**Step 3: Commit**

```bash
git init
git add deno.json .gitignore
git commit -m "feat: scaffold Deno project with deno.json"
```

---

### Task 2: Config files — config.yaml and default.yaml

These are adapted from the E2B versions. Changes from E2B:
- Remove E2B-specific comments/references
- Remove `block-e2b-internals` file rule → replace with `block-sandbox-internals` (generic)
- Remove `block-e2b-internal` network rule → replace with generic sandbox protection
- Remove `block-e2b-interference` command rule → replace with `block-sandbox-interference`
- Update descriptions/messages to say "sandbox" instead of "E2B"

**Files:**
- Create: `config.yaml`
- Create: `default.yaml`

**Step 1: Create `config.yaml`**

Copy from E2B's `config.yaml` with these changes:
- First comment line: `# agentsh server configuration for Deno sandbox`
- Remove `allow_degraded: true` comment about E2B
- Change comment to `# Allow running in sandbox without all features`
- Everything else stays identical (same ports, same security mode, same DLP patterns)

```yaml
# agentsh server configuration for Deno sandbox
# Extends default config with settings optimized for sandbox environment

server:
  http:
    addr: "127.0.0.1:18080"
    read_timeout: "30s"
    write_timeout: "60s"
    max_request_size: "10MB"
  grpc:
    enabled: true
    addr: "127.0.0.1:9090"

auth:
  type: "none"

logging:
  level: "info"
  format: "text"
  output: "stderr"

sessions:
  base_dir: "/var/lib/agentsh/sessions"
  max_sessions: 100
  default_timeout: "1h"
  default_idle_timeout: "15m"
  cleanup_interval: "5m"

audit:
  enabled: true
  storage:
    sqlite_path: "/var/lib/agentsh/events.db"

sandbox:
  enabled: true
  allow_degraded: true  # Allow running in sandbox without all features

  limits:
    max_memory_mb: 4096
    max_cpu_percent: 100
    max_processes: 256

  fuse:
    enabled: true

  network:
    enabled: true
    intercept_mode: "all"
    proxy_listen_addr: "127.0.0.1:0"

  cgroups:
    enabled: true

  seccomp:
    enabled: true

security:
  mode: full
  strict: true

capabilities:
  allow: []

proxy:
  mode: "embedded"
  port: 0
  providers:
    anthropic: "https://api.anthropic.com"
    openai: "https://api.openai.com"

dlp:
  mode: "redact"
  patterns:
    email: true
    phone: true
    credit_card: true
    ssn: true
    api_keys: true
  custom_patterns:
    - name: openai_key
      display: OPENAI_KEY
      regex: "sk-[a-zA-Z0-9]{48,}"
    - name: anthropic_key
      display: ANTHROPIC_KEY
      regex: "sk-ant-[a-zA-Z0-9-]{95,}"
    - name: aws_access_key
      display: AWS_KEY
      regex: "AKIA[0-9A-Z]{16}"
    - name: github_pat
      display: GITHUB_TOKEN
      regex: "ghp_[a-zA-Z0-9]{36}"
    - name: github_oauth
      display: GITHUB_OAUTH
      regex: "gho_[a-zA-Z0-9]{36}"
    - name: jwt_token
      display: JWT
      regex: "eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*"
    - name: private_key
      display: PRIVATE_KEY
      regex: "-----BEGIN [A-Z]+ PRIVATE KEY-----"
    - name: slack_token
      display: SLACK_TOKEN
      regex: "xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"

policies:
  dir: "/etc/agentsh/policies"
  default_policy: "default"

approvals:
  enabled: false
  mode: "async"
  timeout: "5m"

metrics:
  enabled: true
  path: "/metrics"

health:
  path: "/health"
  readiness_path: "/ready"

development:
  disable_auth: true
  verbose_errors: false
```

**Step 2: Create `default.yaml`**

Copy from E2B's `default.yaml` with these changes:

1. Replace the `block-e2b-internals` file rule:
```yaml
  - name: block-sandbox-internals
    description: Block access to sandbox infrastructure binaries and configs
    paths:
      - "/etc/systemd/**"
      - "/run/systemd/**"
    operations:
      - "*"
    decision: deny
    message: "Access to sandbox/system infrastructure blocked: {{.Path}}"
```

2. Replace the `block-e2b-internal` network rule:
```yaml
  - name: block-sandbox-internal
    description: Block sandbox internal services
    cidrs:
      - "192.0.2.0/24"
    decision: deny
    message: "Access to sandbox internal services blocked"
```

3. Replace the `block-e2b-interference` command rule:
```yaml
  - name: block-sandbox-interference
    description: Block commands that could interfere with sandbox infrastructure
    commands:
      - socat
      - iptables
      - ip6tables
      - nft
      - tc
      - ip
    decision: deny
    message: "Command blocked - could interfere with sandbox infrastructure"
```

4. Update the `allow-other-commands` description:
```yaml
  - name: allow-other-commands
    description: Allow remaining commands for sandbox compatibility
    commands:
      - "*"
    decision: allow
```

5. All other rules remain identical to E2B version.

**Step 3: Commit**

```bash
git add config.yaml default.yaml
git commit -m "feat: add agentsh server config and security policy"
```

---

### Task 3: Setup module — setup.ts

The core module that bootstraps agentsh inside a Deno Sandbox.

**Files:**
- Create: `setup.ts`

**Step 1: Create `setup.ts`**

```typescript
import { Sandbox } from "@deno/sandbox";

export interface AgentshSandboxOptions {
  /** GitHub repo for agentsh releases. Default: "erans/agentsh" */
  agentshRepo?: string;
  /** Architecture for .deb package. Default: "amd64" */
  debArch?: string;
  /** Workspace path inside sandbox. Default: "/home/user" */
  workspace?: string;
}

/**
 * Create a Deno Sandbox with agentsh installed, configured, and running.
 *
 * This bootstraps a fresh sandbox by:
 * 1. Installing system dependencies (curl, jq, libseccomp2, sudo)
 * 2. Downloading and installing agentsh from GitHub releases
 * 3. Creating required directories
 * 4. Writing server config and security policy files
 * 5. Starting the agentsh server
 * 6. Installing the shell shim (replaces /bin/bash)
 */
export async function createAgentshSandbox(
  opts?: AgentshSandboxOptions,
): Promise<Sandbox> {
  const repo = opts?.agentshRepo ?? "erans/agentsh";
  const arch = opts?.debArch ?? "amd64";

  // Create sandbox - allow network access for bootstrap (downloading agentsh + packages)
  const sandbox = await Sandbox.create({
    allowNet: true,
  });

  console.log(`Sandbox created: ${sandbox.id}`);

  // Step 1: Install system dependencies
  console.log("Installing system dependencies...");
  await sandbox.sh`apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq libseccomp2 sudo && rm -rf /var/lib/apt/lists/*`;

  // Step 2: Download and install agentsh from GitHub releases
  console.log("Installing agentsh...");
  await sandbox.sh`set -eux; \
    LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" | jq -r '.tag_name'); \
    version="${'${LATEST_TAG#v}'}"; \
    deb="agentsh_${'"${version}"'}_linux_${arch}.deb"; \
    url="https://github.com/${repo}/releases/download/${'${LATEST_TAG}'}/${'"${deb}"'}"; \
    echo "Downloading agentsh ${'${LATEST_TAG}'}: ${'${url}'}"; \
    curl -fsSL -L "${'${url}'}" -o /tmp/agentsh.deb; \
    dpkg -i /tmp/agentsh.deb; \
    rm -f /tmp/agentsh.deb; \
    agentsh --version`;

  // Step 3: Create required directories
  console.log("Creating directories...");
  await sandbox.sh`mkdir -p /etc/agentsh/policies /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh && \
    chmod 755 /etc/agentsh /etc/agentsh/policies && \
    chmod 755 /var/lib/agentsh /var/lib/agentsh/quarantine /var/lib/agentsh/sessions && \
    chmod 755 /var/log/agentsh`;

  // Step 4: Write config and policy files into the sandbox
  console.log("Writing configuration files...");
  const configYaml = await Deno.readTextFile(
    new URL("./config.yaml", import.meta.url),
  );
  const policyYaml = await Deno.readTextFile(
    new URL("./default.yaml", import.meta.url),
  );

  // Write files using sandbox filesystem API if available, otherwise via sh
  if (sandbox.fs && typeof sandbox.fs.writeTextFile === "function") {
    await sandbox.fs.writeTextFile("/etc/agentsh/config.yaml", configYaml);
    await sandbox.fs.writeTextFile(
      "/etc/agentsh/policies/default.yaml",
      policyYaml,
    );
  } else {
    // Fallback: write via heredoc in shell
    // Escape single quotes for shell safety
    const escapedConfig = configYaml.replaceAll("'", "'\\''");
    const escapedPolicy = policyYaml.replaceAll("'", "'\\''");
    await sandbox.sh`cat > /etc/agentsh/config.yaml << 'AGENTSH_CONFIG_EOF'
${escapedConfig}
AGENTSH_CONFIG_EOF`;
    await sandbox.sh`cat > /etc/agentsh/policies/default.yaml << 'AGENTSH_POLICY_EOF'
${escapedPolicy}
AGENTSH_POLICY_EOF`;
  }

  // Step 5: Set permissions
  await sandbox.sh`chown -R user:user /var/lib/agentsh /var/log/agentsh /etc/agentsh`;

  // Step 6: Give user passwordless sudo for agentsh
  await sandbox.sh`echo "user ALL=(ALL) NOPASSWD: /usr/bin/agentsh" >> /etc/sudoers`;

  // Step 7: Set environment variable
  if (sandbox.env && typeof sandbox.env.set === "function") {
    await sandbox.env.set("AGENTSH_SERVER", "http://127.0.0.1:18080");
  }

  // Step 8: Start agentsh server in background
  console.log("Starting agentsh server...");
  await sandbox.sh`agentsh server &`;

  // Wait for server to be ready
  console.log("Waiting for server to be ready...");
  await sandbox.sh`for i in $(seq 1 30); do \
    if curl -s http://127.0.0.1:18080/health > /dev/null 2>&1; then \
      echo "agentsh server ready"; \
      exit 0; \
    fi; \
    sleep 0.5; \
  done; \
  echo "agentsh server failed to start" >&2; \
  exit 1`;

  // Step 9: Install shell shim
  console.log("Installing shell shim...");
  await sandbox.sh`sudo agentsh shim install-shell --root / --shim /usr/bin/agentsh-shell-shim --bash --i-understand-this-modifies-the-host`;

  console.log("agentsh sandbox ready.");
  return sandbox;
}
```

**Important notes about the shell interpolation:**
- The `sandbox.sh` tagged template literal may or may not support shell variable expansion. The exact behavior depends on the `@deno/sandbox` SDK.
- If `sandbox.sh` interpolates template variables as literal strings (not shell expansion), the agentsh download step needs to use a single string command instead. We'll adjust when testing.
- The `sandbox.fs` API is used optimistically — if `writeTextFile` doesn't exist, we fall back to heredocs via shell.

**Step 2: Commit**

```bash
git add setup.ts
git commit -m "feat: add agentsh sandbox bootstrap module"
```

---

### Task 4: Demo — demo-blocking.ts

Demonstrates command policy enforcement inside the Deno Sandbox.

**Files:**
- Create: `demo-blocking.ts`

**Step 1: Create `demo-blocking.ts`**

Adapted from E2B's `demo-blocking.ts`. Changes:
- Import `createAgentshSandbox` from `./setup.ts` instead of using `Sandbox.create('e2b-agentsh')`
- Use `sandbox.sh` instead of `sbx.commands.run()`
- Use `sandbox.kill()` or `sandbox.close()` for cleanup
- Load `DENO_DEPLOY_TOKEN` from env (via `Deno.env.get`)

```typescript
import { createAgentshSandbox } from "./setup.ts";

async function main() {
  console.log("Creating agentsh sandbox...");
  const sandbox = await createAgentshSandbox();

  try {
    // Create a session
    console.log("\n=== Creating agentsh session ===");
    const createSession = await sandbox.sh`agentsh session create --workspace /home/user --json`;
    const sessionData = JSON.parse(createSession.stdout);
    const sessionId = sessionData.id;
    console.log(`Session ID: ${sessionId}\n`);

    console.log("=".repeat(60));
    console.log("DEMONSTRATING AGENTSH POLICY BLOCKING");
    console.log("=".repeat(60));

    // Helper to run via agentsh exec with session
    async function runAgentsh(
      description: string,
      command: string,
      args: string[] = [],
    ) {
      console.log(`\n--- ${description} ---`);
      const json = JSON.stringify({ command, args });
      try {
        const result =
          await sandbox.sh`agentsh exec ${sessionId} --json ${json} 2>&1`;
        console.log(`  ALLOWED (exit: ${result.exitCode})`);
        return true;
      } catch (e: unknown) {
        const output = (e as { stdout?: string }).stdout ?? "";
        if (output.includes("denied by policy")) {
          const ruleMatch = output.match(/rule=([^\)]+)/);
          const rule = ruleMatch ? ruleMatch[1] : "unknown";
          console.log(`  BLOCKED by policy rule: ${rule}`);
        } else {
          console.log(
            `  BLOCKED (exit: ${(e as { exitCode?: number }).exitCode})`,
          );
        }
        return false;
      }
    }

    console.log("\n=== 1. ALLOWED COMMANDS ===");
    await runAgentsh("/bin/echo Hello", "/bin/echo", ["Hello"]);
    await runAgentsh("/bin/pwd", "/bin/pwd");
    await runAgentsh("/bin/ls /home", "/bin/ls", ["/home"]);
    await runAgentsh("/bin/date", "/bin/date");
    await runAgentsh("/usr/bin/python3 -c print(1)", "/usr/bin/python3", [
      "-c",
      "print(1)",
    ]);
    await runAgentsh("/usr/bin/git --version", "/usr/bin/git", ["--version"]);

    console.log("\n=== 2. BLOCKED: Privilege Escalation ===");
    await runAgentsh("/usr/bin/sudo whoami", "/usr/bin/sudo", ["whoami"]);
    await runAgentsh("/bin/su -", "/bin/su", ["-"]);
    await runAgentsh("/usr/sbin/chroot /", "/usr/sbin/chroot", ["/"]);

    console.log("\n=== 3. BLOCKED: Network Tools ===");
    await runAgentsh("/usr/bin/ssh localhost", "/usr/bin/ssh", ["localhost"]);
    await runAgentsh("/bin/nc -h", "/bin/nc", ["-h"]);

    console.log("\n=== 4. BLOCKED: System Commands ===");
    await runAgentsh("/bin/kill -9 1", "/bin/kill", ["-9", "1"]);
    await runAgentsh("/sbin/shutdown now", "/sbin/shutdown", ["now"]);
    await runAgentsh("/usr/bin/systemctl status", "/usr/bin/systemctl", [
      "status",
    ]);

    console.log("\n=== 5. BLOCKED: Recursive Delete ===");
    await sandbox.sh`mkdir -p /tmp/test && touch /tmp/test/file.txt`;
    await runAgentsh("/bin/rm -rf /tmp/test", "/bin/rm", ["-rf", "/tmp/test"]);
    await runAgentsh("/bin/rm -r /tmp/test", "/bin/rm", ["-r", "/tmp/test"]);

    console.log("\n=== 6. ALLOWED: Single File Delete ===");
    await sandbox.sh`mkdir -p /tmp/test && touch /tmp/test/file.txt`;
    await runAgentsh("/bin/rm /tmp/test/file.txt", "/bin/rm", [
      "/tmp/test/file.txt",
    ]);

    console.log("\n" + "=".repeat(60));
    console.log("DEMO COMPLETE");
    console.log("=".repeat(60));
  } catch (error) {
    console.error("Error:", error);
  } finally {
    console.log("\nCleaning up...");
    await sandbox.close();
    console.log("Done.");
  }
}

main().catch(console.error);
```

**Step 2: Commit**

```bash
git add demo-blocking.ts
git commit -m "feat: add command blocking demo"
```

---

### Task 5: Demo — demo-network.ts

Demonstrates network policy enforcement.

**Files:**
- Create: `demo-network.ts`

**Step 1: Create `demo-network.ts`**

Same pattern as E2B's `demo-network.ts`, adapted for Deno Sandbox API.

```typescript
import { createAgentshSandbox } from "./setup.ts";

async function main() {
  console.log("Creating agentsh sandbox...");
  const sandbox = await createAgentshSandbox();

  try {
    // Create a session
    console.log("\n=== Creating agentsh session ===");
    const createSession = await sandbox.sh`agentsh session create --workspace /home/user --json`;
    const sessionData = JSON.parse(createSession.stdout);
    const sessionId = sessionData.id;
    console.log(`Session ID: ${sessionId}\n`);

    console.log("=".repeat(70));
    console.log("DEMONSTRATING AGENTSH NETWORK POLICY BLOCKING");
    console.log("=".repeat(70));

    async function runAgentsh(
      description: string,
      command: string,
      args: string[] = [],
    ) {
      console.log(`\n--- ${description} ---`);
      console.log(`Command: ${command} ${args.join(" ")}`);
      const json = JSON.stringify({ command, args });
      try {
        const result =
          await sandbox.sh`agentsh exec ${sessionId} --json ${json} 2>&1`;
        const output = result.stdout.trim();
        console.log(`Exit code: ${result.exitCode}`);
        if (output) {
          const preview = output.substring(0, 150).replace(/\n/g, " ");
          console.log(`Output: ${preview}${output.length > 150 ? "..." : ""}`);
        }
        return { allowed: true, output };
      } catch (e: unknown) {
        const err = e as { stdout?: string; exitCode?: number };
        const output = err.stdout ?? "";
        console.log(`Exit code: ${err.exitCode}`);
        if (output.includes("denied by policy")) {
          const ruleMatch = output.match(/rule=([^\)]+)/);
          const rule = ruleMatch ? ruleMatch[1] : "unknown";
          console.log(`BLOCKED by policy: ${rule}`);
        } else {
          const preview = output.substring(0, 150).replace(/\n/g, " ");
          console.log(`Output: ${preview}`);
        }
        return { allowed: false, output };
      }
    }

    // Test 1: Localhost
    console.log("\n" + "=".repeat(70));
    console.log("1. LOCALHOST - Should be ALLOWED");
    console.log("=".repeat(70));
    await runAgentsh("curl localhost:18080/health", "/usr/bin/curl", [
      "-s",
      "-w",
      "\\nHTTP_CODE:%{http_code}",
      "http://127.0.0.1:18080/health",
    ]);

    // Test 2: Cloud Metadata
    console.log("\n" + "=".repeat(70));
    console.log("2. CLOUD METADATA - Should be BLOCKED");
    console.log("=".repeat(70));
    await runAgentsh("curl http://169.254.169.254/", "/usr/bin/curl", [
      "-s",
      "-w",
      "\\nHTTP_CODE:%{http_code}",
      "--connect-timeout",
      "5",
      "http://169.254.169.254/",
    ]);

    // Test 3: Private Networks
    console.log("\n" + "=".repeat(70));
    console.log("3. PRIVATE NETWORKS - Should be BLOCKED");
    console.log("=".repeat(70));
    await runAgentsh("curl http://10.0.0.1/", "/usr/bin/curl", [
      "-s",
      "--connect-timeout",
      "3",
      "http://10.0.0.1/",
    ]);
    await runAgentsh("curl http://192.168.1.1/", "/usr/bin/curl", [
      "-s",
      "--connect-timeout",
      "3",
      "http://192.168.1.1/",
    ]);

    // Test 4: Package Registries
    console.log("\n" + "=".repeat(70));
    console.log("4. PACKAGE REGISTRIES - Should be ALLOWED");
    console.log("=".repeat(70));
    await runAgentsh("curl https://registry.npmjs.org/", "/usr/bin/curl", [
      "-s",
      "-w",
      "\\nHTTP_CODE:%{http_code}",
      "--connect-timeout",
      "10",
      "-o",
      "/dev/null",
      "https://registry.npmjs.org/",
    ]);
    await runAgentsh("curl https://pypi.org/", "/usr/bin/curl", [
      "-s",
      "-w",
      "\\nHTTP_CODE:%{http_code}",
      "--connect-timeout",
      "10",
      "-o",
      "/dev/null",
      "https://pypi.org/",
    ]);

    // Test 5: Unknown domains
    console.log("\n" + "=".repeat(70));
    console.log("5. UNKNOWN DOMAINS - Should be BLOCKED");
    console.log("=".repeat(70));
    await runAgentsh("curl https://example.com/", "/usr/bin/curl", [
      "-s",
      "--connect-timeout",
      "5",
      "-o",
      "/dev/null",
      "https://example.com/",
    ]);

    console.log("\n" + "=".repeat(70));
    console.log("NETWORK DEMO COMPLETE");
    console.log("=".repeat(70));
  } catch (error) {
    console.error("Error:", error);
  } finally {
    console.log("\nCleaning up...");
    await sandbox.close();
    console.log("Done.");
  }
}

main().catch(console.error);
```

**Step 2: Commit**

```bash
git add demo-network.ts
git commit -m "feat: add network blocking demo"
```

---

### Task 6: Test script — test-sandbox.ts

Verifies the sandbox is correctly set up.

**Files:**
- Create: `test-sandbox.ts`

**Step 1: Create `test-sandbox.ts`**

```typescript
import { createAgentshSandbox } from "./setup.ts";

async function main() {
  console.log("Creating agentsh sandbox...");
  const sandbox = await createAgentshSandbox();
  let passed = 0;
  let failed = 0;

  function pass(name: string, detail?: string) {
    passed++;
    console.log(`  PASS: ${name}${detail ? ` — ${detail}` : ""}`);
  }

  function fail(name: string, detail?: string) {
    failed++;
    console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ""}`);
  }

  try {
    // Test 1: agentsh is installed
    console.log("\n=== Test 1: agentsh installation ===");
    const version = await sandbox.sh`agentsh --version`;
    if (version.stdout.includes("agentsh")) {
      pass("agentsh installed", version.stdout.trim());
    } else {
      fail("agentsh installed", "unexpected output");
    }

    // Test 2: Server is running
    console.log("\n=== Test 2: agentsh server health ===");
    const health = await sandbox.sh`curl -s http://127.0.0.1:18080/health`;
    if (health.stdout.trim() === "ok") {
      pass("server health", "ok");
    } else {
      fail("server health", health.stdout.trim());
    }

    // Test 3: Policy file exists
    console.log("\n=== Test 3: Policy file ===");
    const policyHead =
      await sandbox.sh`head -5 /etc/agentsh/policies/default.yaml`;
    if (policyHead.stdout.includes("version")) {
      pass("policy file exists");
    } else {
      fail("policy file exists");
    }

    // Test 4: Config file exists
    console.log("\n=== Test 4: Config file ===");
    const configHead = await sandbox.sh`head -5 /etc/agentsh/config.yaml`;
    if (configHead.stdout.includes("server")) {
      pass("config file exists");
    } else {
      fail("config file exists");
    }

    // Test 5: Shell shim installed
    console.log("\n=== Test 5: Shell shim ===");
    const bashReal =
      await sandbox.sh`file /bin/bash.real 2>/dev/null || echo "NOT_FOUND"`;
    if (!bashReal.stdout.includes("NOT_FOUND")) {
      pass("shell shim installed", "/bin/bash.real exists");
    } else {
      fail("shell shim not installed", "/bin/bash.real not found");
    }

    // Test 6: Command execution through shim
    console.log("\n=== Test 6: Command through shim ===");
    const shimTest =
      await sandbox.sh`/bin/bash -c "echo hello_from_shim"`;
    if (shimTest.stdout.includes("hello_from_shim")) {
      pass("shim command execution");
    } else {
      fail("shim command execution", shimTest.stdout.trim());
    }

    // Test 7: Session creation
    console.log("\n=== Test 7: Session creation ===");
    const session =
      await sandbox.sh`agentsh session create --workspace /home/user --json`;
    try {
      const sessionData = JSON.parse(session.stdout);
      if (sessionData.id) {
        pass("session creation", `id=${sessionData.id}`);
      } else {
        fail("session creation", "no id in response");
      }
    } catch {
      fail("session creation", "invalid JSON response");
    }

    // Summary
    console.log("\n" + "=".repeat(40));
    console.log(`Results: ${passed} passed, ${failed} failed`);
    console.log("=".repeat(40));

    if (failed > 0) {
      Deno.exit(1);
    }
  } catch (error) {
    console.error("Test error:", error);
    Deno.exit(1);
  } finally {
    await sandbox.close();
  }
}

main().catch(console.error);
```

**Step 2: Commit**

```bash
git add test-sandbox.ts
git commit -m "feat: add sandbox verification tests"
```

---

### Task 7: LICENSE and .env

**Files:**
- Create: `LICENSE`
- Create: `.env` (template only — not committed)

**Step 1: Create LICENSE**

MIT license, same as E2B version.

```
MIT License

Copyright (c) 2026 Canyon Road

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**Step 2: Create `.env` (not committed)**

```
DENO_DEPLOY_TOKEN=your_token_here
```

**Step 3: Commit**

```bash
git add LICENSE
git commit -m "feat: add MIT license"
```

---

### Task 8: Verify and adjust for actual @deno/sandbox API

Since the full `@deno/sandbox` API docs aren't available yet, this task is for testing and fixing API mismatches.

**Step 1: Install dependencies and check types**

```bash
cd /home/eran/work/canyonroad/agentsh-deno
deno check setup.ts
```

**Step 2: Fix any type errors based on actual API**

Likely adjustments:
- `Sandbox.create()` options may differ (e.g., `allowNet` might be a different shape)
- `sandbox.sh` return type may have different property names (e.g., `output` vs `stdout`)
- `sandbox.fs.writeTextFile` may not exist — fallback to heredoc approach
- `sandbox.env.set` may not exist — use `export` in shell
- `sandbox.close()` vs `sandbox.kill()` vs `sandbox[Symbol.dispose]()`

**Step 3: Fix any issues and commit**

```bash
git add -u
git commit -m "fix: adjust API calls to match @deno/sandbox SDK"
```

---

## Summary

| Task | Description | Key Files |
|------|-------------|-----------|
| 1 | Project scaffolding | `deno.json`, `.gitignore` |
| 2 | Config files | `config.yaml`, `default.yaml` |
| 3 | Bootstrap module | `setup.ts` |
| 4 | Command blocking demo | `demo-blocking.ts` |
| 5 | Network blocking demo | `demo-network.ts` |
| 6 | Verification tests | `test-sandbox.ts` |
| 7 | License and env | `LICENSE`, `.env` |
| 8 | API verification | Fix any SDK mismatches |
