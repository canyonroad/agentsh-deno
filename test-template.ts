/**
 * test-template.ts — Comprehensive security test suite for agentsh + Deno Sandbox.
 *
 * Creates a sandbox via `createAgentshSandbox()`, then runs 50+ security tests
 * across 10 categories to verify all agentsh enforcement layers.
 *
 * Usage:
 *   deno run --allow-net --allow-env --allow-read --env-file=.env test-template.ts
 */

import { createAgentshSandbox } from "./setup.ts";
import type { Sandbox } from "@deno/sandbox";

const AGENTSH_API = "http://127.0.0.1:18080";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ExecResponse {
  result?: {
    exit_code?: number;
    stdout?: string;
    stderr?: string;
    error?: {
      code?: string;
      message?: string;
      policy_rule?: string;
    };
  };
  guidance?: {
    status?: string;
    blocked?: boolean;
    reason?: string;
    policy_rule?: string;
  };
  events?: {
    blocked_operations?: Array<{
      policy?: { rule?: string; message?: string };
    }>;
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  let passed = 0;
  let failed = 0;
  let serverDead = false;
  let consecutiveErrors = 0;

  async function test(name: string, fn: () => Promise<boolean>) {
    if (serverDead) {
      process.stdout.write(`  ${name}... `);
      console.log("SKIPPED (server unreachable)");
      failed++;
      return;
    }
    process.stdout.write(`  ${name}... `);
    try {
      if (await fn()) {
        console.log("PASS");
        passed++;
        consecutiveErrors = 0;
      } else {
        console.log("FAIL");
        failed++;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`ERROR: ${msg.slice(0, 120)}`);
      failed++;
      if (
        msg.includes("Connection") ||
        msg.includes("closed") ||
        msg.includes("timeout")
      ) {
        consecutiveErrors++;
        if (consecutiveErrors >= 2) {
          serverDead = true;
          console.log(
            "  !! Server appears unreachable — skipping remaining tests",
          );
        }
      }
    }
    await new Promise((r) => setTimeout(r, 200));
  }

  console.log("Creating sandbox with agentsh v0.16.8...");
  const sandbox = await createAgentshSandbox({
    envVars: {
      // Inject test secrets that env_policy should hide
      AWS_SECRET_ACCESS_KEY: "AKIAIOSFODNN7EXAMPLE",
      AWS_SESSION_TOKEN: "FwoGZXIvY-test-token",
      OPENAI_API_KEY: "sk-test-openai-key-67890",
      DATABASE_URL: "postgresql://admin:s3cret@db.internal:5432/prod",
      SECRET_SIGNING_KEY: "hmac-sha256-test-key",
      MY_CUSTOM_SETTING: "this-is-not-in-allow-list",
    },
  });
  console.log("");

  try {
    // =========================================================================
    // 1. INSTALLATION
    // =========================================================================
    console.log("=== Installation ===");

    await test("agentsh installed", async () => {
      const r = (await sandbox.sh`agentsh --version`.text()).trim();
      return r.includes("agentsh") && r.includes("0.16.8");
    });

    // =========================================================================
    // 2. SERVER & CONFIGURATION
    // =========================================================================
    console.log("\n=== Server & Configuration ===");

    await test("server healthy", async () => {
      const r = (
        await sandbox.sh`curl -s http://127.0.0.1:18080/health`.text()
      ).trim();
      return r === "ok";
    });

    await test("server process running", async () => {
      const r = await sandbox
        .sh`ps aux | grep "agentsh server" | grep -v grep`
        .noThrow()
        .text();
      return r.includes("agentsh");
    });

    await test("policy file exists", async () => {
      const r = await sandbox
        .sh`head -5 /etc/agentsh/policies/default.yaml`
        .text();
      return r.includes("version");
    });

    await test("config file exists", async () => {
      const r = await sandbox.sh`head -5 /etc/agentsh/config.yaml`.text();
      return r.includes("server");
    });

    await test("real_paths enabled in config", async () => {
      const r = await sandbox
        .sh`grep real_paths /etc/agentsh/config.yaml`
        .text();
      return r.includes("true");
    });

    await test("BASH_ENV configured", async () => {
      const r = await sandbox
        .sh`grep BASH_ENV /etc/agentsh/config.yaml`
        .text();
      return r.includes("bash_startup.sh");
    });

    // =========================================================================
    // 3. SHELL SHIM
    // =========================================================================
    console.log("\n=== Shell Shim ===");

    await test("shim binary exists", async () => {
      const r = await sandbox
        .sh`test -x /usr/bin/agentsh-shell-shim && echo OK || echo MISSING`
        .text();
      return r.includes("OK");
    });

    await test("real bash preserved (/bin/bash.real)", async () => {
      const r = await sandbox
        .sh`test -f /bin/bash.real && echo EXISTS || echo MISSING`
        .text();
      return r.includes("EXISTS");
    });

    await test("echo through shim", async () => {
      const r = (
        await sandbox.sh`/bin/bash -c "echo hello-shim"`.text()
      ).trim();
      return r.includes("hello-shim");
    });

    // =========================================================================
    // 4. SECURITY DIAGNOSTICS (via agentsh detect)
    // =========================================================================
    console.log("\n=== Security Diagnostics ===");

    const detectOutput = (
      await sandbox.sh`agentsh detect 2>&1`.noThrow().text()
    );
    const detectLine = (name: string) =>
      detectOutput.split("\n").some(
        (line) => line.includes(name) && line.includes("\u2713"),
      );

    await test("agentsh detect: seccomp available", async () => {
      return detectLine("seccomp");
    });

    await test("agentsh detect: ptrace available", async () => {
      return detectLine("ptrace");
    });

    await test("agentsh detect: landlock available", async () => {
      return detectLine("landlock");
    });

    await test("agentsh detect: capabilities reported", async () => {
      const d = detectOutput.toLowerCase();
      return d.includes("file protection") &&
        d.includes("command control") &&
        d.includes("network");
    });

    // =========================================================================
    // CREATE AGENTSH SESSION
    // =========================================================================
    console.log("\n--- Creating session ---");

    const sessionText = (
      await sandbox.sh`agentsh session create --workspace /app --json`.text()
    ).trim();
    const sessionId: string = JSON.parse(sessionText).id;
    console.log(`Session ID: ${sessionId}`);

    await new Promise((r) => setTimeout(r, 1500));

    // -----------------------------------------------------------------------
    // Helper: execute via agentsh session API
    // -----------------------------------------------------------------------
    let reqCounter = 0;

    async function exec(
      command: string,
      args: string[] = [],
    ): Promise<{
      exitCode: number;
      stdout: string;
      stderr: string;
      blocked: boolean;
      denied: boolean;
      rule: string;
    }> {
      const body = JSON.stringify({ command, args });
      const escapedBody = body.replace(/'/g, "'\\''");
      const reqFile = `/tmp/exec-req-${++reqCounter}.json`;

      await sandbox.fs.writeTextFile(
        reqFile,
        `#!/bin/sh
rm -f /tmp/exec-result.json
curl -s -X POST "${AGENTSH_API}/api/v1/sessions/${sessionId}/exec" \
  -H "Content-Type: application/json" \
  --connect-timeout 10 \
  --max-time 30 \
  -d '${escapedBody}' \
  -o /tmp/exec-result.json 2>/dev/null
`,
      );

      await sandbox.sh`/bin/sh ${reqFile}`.noThrow().result();

      let output: string;
      try {
        output = await sandbox.fs.readTextFile("/tmp/exec-result.json");
      } catch {
        return {
          exitCode: -1,
          stdout: "",
          stderr: "no API response",
          blocked: false,
          denied: false,
          rule: "",
        };
      }

      try {
        const json: ExecResponse = JSON.parse(output.trim());

        // Policy denial
        if (json.result?.error?.code === "E_POLICY_DENIED") {
          const rule = json.result.error.policy_rule ?? "unknown";
          return {
            exitCode: -1,
            stdout: "",
            stderr: json.result.error.message ?? "",
            blocked: true,
            denied: true,
            rule,
          };
        }

        // Blocked operations in events
        const blockedOps = json.events?.blocked_operations ?? [];
        if (blockedOps.length > 0) {
          const rule = blockedOps[0].policy?.rule ?? "unknown";
          return {
            exitCode: -1,
            stdout: "",
            stderr: "",
            blocked: true,
            denied: true,
            rule,
          };
        }

        // Guidance blocked
        if (json.guidance?.blocked || json.guidance?.status === "blocked") {
          const rule = json.guidance?.policy_rule ?? "unknown";
          return {
            exitCode: -1,
            stdout: "",
            stderr: json.guidance?.reason ?? "",
            blocked: true,
            denied: true,
            rule,
          };
        }

        const exitCode = json.result?.exit_code ?? -1;
        const stdout = json.result?.stdout ?? "";
        const stderr = json.result?.stderr ?? "";
        const denied =
          stderr.includes("Permission denied") || stderr.includes("denied");
        return { exitCode, stdout, stderr, blocked: false, denied, rule: "" };
      } catch {
        return {
          exitCode: -1,
          stdout: "",
          stderr: `parse error: ${output.slice(0, 200)}`,
          blocked: false,
          denied: false,
          rule: "",
        };
      }
    }

    async function execSh(shellCmd: string) {
      return exec("/bin/bash.real", [
        "-c",
        `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; ${shellCmd}`,
      ]);
    }

    // Warmup
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        await execSh("echo warmup-ok");
        break;
      } catch {
        if (attempt === 3) {
          console.log("  Warmup failed — server may be unreachable");
          serverDead = true;
        } else {
          console.log(`  Warmup attempt ${attempt} failed, retrying...`);
          await new Promise((r) => setTimeout(r, attempt * 2000));
        }
      }
    }

    // =========================================================================
    // 5. COMMAND POLICY ENFORCEMENT
    // =========================================================================
    console.log("\n=== Command Policy Enforcement ===");

    await test("sudo blocked", async () => {
      const r = await exec("/usr/bin/sudo", ["whoami"]);
      return r.blocked && r.rule.includes("block-shell-escape");
    });

    await test("su blocked", async () => {
      const r = await exec("/usr/bin/su", ["-"]);
      return r.blocked || r.denied;
    });

    await test("ssh blocked", async () => {
      const r = await exec("/usr/bin/ssh", ["localhost"]);
      return r.blocked && r.rule.includes("block-network-tools");
    });

    await test("kill blocked", async () => {
      const r = await exec("/usr/bin/kill", ["-9", "1"]);
      return r.blocked && r.rule.includes("block-system-commands");
    });

    await test("rm -rf blocked", async () => {
      await execSh("mkdir -p /tmp/testdir && touch /tmp/testdir/f.txt");
      const r = await exec("/usr/bin/rm", ["-rf", "/tmp/testdir"]);
      return r.blocked && r.rule.includes("block-rm-recursive");
    });

    await test("echo allowed", async () => {
      const r = await exec("/bin/echo", ["policy-test"]);
      return r.exitCode === 0 && r.stdout.includes("policy-test");
    });

    await test("git allowed", async () => {
      const r = await exec("/usr/bin/git", ["--version"]);
      return r.exitCode === 0 && r.stdout.includes("git");
    });

    // =========================================================================
    // 6. NETWORK POLICY
    // =========================================================================
    console.log("\n=== Network Policy ===");

    await test("package registry allowed (npmjs.org)", async () => {
      for (let attempt = 0; attempt < 3; attempt++) {
        const r = await execSh(
          '/usr/bin/curl -s --connect-timeout 10 --max-time 15 -o /dev/null -w "%{http_code}" https://registry.npmjs.org/',
        );
        const code = parseInt(r.stdout.trim(), 10);
        if (code >= 200 && code < 400) return true;
        if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 2000));
      }
      return false;
    });

    await test("metadata endpoint blocked (169.254.169.254)", async () => {
      const r = await execSh(
        '/usr/bin/curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://169.254.169.254/',
      );
      return r.stdout.includes("403") || r.exitCode !== 0;
    });

    await test("private network blocked (10.0.0.1)", async () => {
      const r = await execSh(
        '/usr/bin/curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://10.0.0.1/',
      );
      return r.stdout.includes("403") || r.exitCode !== 0;
    });

    // =========================================================================
    // 7. ENVIRONMENT POLICY
    // =========================================================================
    console.log("\n=== Environment Policy ===");

    await test("sensitive vars filtered (AWS_, OPENAI_, etc.)", async () => {
      const r = await execSh("/usr/bin/env 2>/dev/null | sort || echo ''");
      const blocked = [
        "AWS_",
        "AZURE_",
        "GOOGLE_",
        "OPENAI_",
        "ANTHROPIC_",
        "DATABASE_URL",
        "SECRET_",
      ];
      for (const prefix of blocked) {
        if (r.stdout.includes(prefix)) return false;
      }
      return true;
    });

    await test("safe vars present (HOME, PATH)", async () => {
      const r = await exec("/bin/bash.real", [
        "-c",
        'echo "HOME=$HOME" && echo "PATH=$PATH"',
      ]);
      return r.stdout.includes("HOME=/") && r.stdout.includes("PATH=/");
    });

    await test("BASH_ENV set in session", async () => {
      const r = await execSh("echo $BASH_ENV");
      return r.stdout.includes("bash_startup");
    });

    await test("unlisted var hidden (MY_CUSTOM_SETTING)", async () => {
      const r = await exec("/usr/bin/printenv", ["MY_CUSTOM_SETTING"]);
      return r.exitCode !== 0 || !r.stdout.includes("this-is-not");
    });

    // =========================================================================
    // 8. FILE I/O ENFORCEMENT
    // Note: Without FUSE (no /dev/fuse in Firecracker), file_rules are not
    // kernel-enforced. These tests verify OS-level permissions which may
    // or may not block writes depending on the sandbox user's privileges.
    // =========================================================================
    console.log("\n=== File I/O Enforcement ===");

    // Allowed
    await test("write to workspace succeeds", async () => {
      const r = await execSh(
        'echo "fileio-test" > /app/fileio-test.txt && cat /app/fileio-test.txt',
      );
      return r.exitCode === 0 && r.stdout.includes("fileio-test");
    });

    await test("write to /tmp succeeds", async () => {
      const r = await execSh(
        'echo "tmp-test" > /tmp/fileio-test.txt && cat /tmp/fileio-test.txt',
      );
      return r.exitCode === 0 && r.stdout.includes("tmp-test");
    });

    await test("read system files succeeds", async () => {
      const r = await execSh("cat /etc/hosts");
      return r.exitCode === 0 && r.stdout.trim().length > 0;
    });

    // =========================================================================
    // 9. MULTI-CONTEXT COMMAND BLOCKING
    // Direct exec API calls (not nested shell) are policy-enforced.
    // =========================================================================
    console.log("\n=== Multi-Context Command Blocking ===");

    await test("direct /usr/bin/sudo blocked", async () => {
      const r = await exec("/usr/bin/sudo", ["whoami"]);
      return r.blocked || r.denied;
    });

    await test("direct /usr/bin/su blocked", async () => {
      const r = await exec("/usr/bin/su", ["root", "-c", "whoami"]);
      return r.blocked || r.denied;
    });

    await test("direct /usr/bin/ssh blocked", async () => {
      const r = await exec("/usr/bin/ssh", ["localhost"]);
      return r.blocked || r.denied;
    });

    // Allowed: safe commands via same contexts
    await test("env whoami allowed", async () => {
      const r = await execSh("/usr/bin/env /usr/bin/whoami");
      return r.exitCode === 0;
    });

    await test("find -exec echo allowed", async () => {
      const r = await execSh(
        "/usr/bin/find /tmp -maxdepth 0 -exec /usr/bin/echo found \\;",
      );
      return r.exitCode === 0 && r.stdout.includes("found");
    });

    // =========================================================================
    // 10. CREDENTIAL BLOCKING (via exec API policy)
    // =========================================================================
    console.log("\n=== Credential Blocking ===");

    await test("read /root/.ssh/id_rsa blocked", async () => {
      const r = await exec("/usr/bin/cat", ["/root/.ssh/id_rsa"]);
      return r.denied || r.exitCode !== 0;
    });

    await test("read /root/.aws/credentials blocked", async () => {
      const r = await exec("/usr/bin/cat", ["/root/.aws/credentials"]);
      return r.denied || r.exitCode !== 0;
    });

    // =========================================================================
    // RESULTS
    // =========================================================================
    console.log("\n" + "=".repeat(60));
    console.log(
      `RESULTS: ${passed} passed, ${failed} failed out of ${passed + failed}`,
    );
    console.log("=".repeat(60));
  } catch (error) {
    console.error("Fatal:", error);
    failed++;
  } finally {
    console.log("\nCleaning up sandbox...");
    await sandbox.close();
    console.log("Done.");
  }

  Deno.exit(failed > 0 ? 1 : 0);
}

// deno-lint-ignore no-explicit-any
const process = { stdout: { write: (s: string) => Deno.stdout.writeSync(new TextEncoder().encode(s)) } } as any;

main();
