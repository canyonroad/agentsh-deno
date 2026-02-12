/**
 * detect-sandbox.ts -- Diagnostic script to verify whether FUSE, Landlock,
 * and other kernel security features are actually working inside the Deno
 * sandbox running agentsh.
 *
 * Checks:
 *   1. `agentsh detect`       -- kernel feature detection summary
 *   2. `agentsh detect config` -- configuration-level detection (if available)
 *   3. Server log inspection   -- FUSE/Landlock related messages
 *   4. Landlock enforcement    -- attempt to read a denied path via shim vs direct
 *   5. FUSE mount check        -- look for fuse mounts
 *   6. Cleanup
 *
 * Usage:
 *   deno run --allow-all --env-file=.env detect-sandbox.ts
 */

import { createAgentshSandbox } from "./setup.ts";

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
}

interface SessionCreateResponse {
  id: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function banner(title: string): void {
  const line = "=".repeat(70);
  console.log(`\n${line}`);
  console.log(`  ${title}`);
  console.log(line);
}

function subBanner(title: string): void {
  console.log(`\n--- ${title} ---\n`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("detect-sandbox.ts: Diagnosing FUSE and Landlock inside Deno sandbox\n");

  const sandbox = await createAgentshSandbox();

  try {
    // =====================================================================
    // 1. agentsh detect -- kernel feature detection
    // =====================================================================
    banner("1. agentsh detect (kernel feature detection)");

    try {
      const detectText = await sandbox.sh`agentsh detect`.noThrow().text();
      console.log(detectText);
    } catch (err) {
      console.log(`Error running 'agentsh detect': ${err}`);
    }

    subBanner("1b. agentsh detect -o json");
    try {
      const detectJson = await sandbox.sh`agentsh detect -o json`.noThrow().text();
      console.log(detectJson);
    } catch (err) {
      console.log(`Error running 'agentsh detect -o json': ${err}`);
    }

    // =====================================================================
    // 2. agentsh detect config (if available)
    // =====================================================================
    banner("2. agentsh detect config (configuration detection)");

    try {
      const detectConfig = await sandbox.sh`agentsh detect config 2>&1`.noThrow().text();
      console.log(detectConfig);
    } catch (err) {
      console.log(`Error or not available: ${err}`);
    }

    // Also try subcommand variants in case the CLI uses a different syntax
    try {
      const detectConfig2 = await sandbox.sh`agentsh detect --config 2>&1`.noThrow().text();
      if (detectConfig2.trim()) {
        subBanner("2b. agentsh detect --config");
        console.log(detectConfig2);
      }
    } catch {
      // silently ignore
    }

    // =====================================================================
    // 3. Server log inspection for FUSE/Landlock messages
    // =====================================================================
    banner("3. Server log inspection (/var/log/agentsh/)");

    subBanner("3a. Files in /var/log/agentsh/");
    try {
      const logLs = await sandbox.sh`ls -la /var/log/agentsh/ 2>&1`.noThrow().text();
      console.log(logLs);
    } catch (err) {
      console.log(`Error listing log dir: ${err}`);
    }

    subBanner("3b. Searching logs for FUSE-related messages");
    try {
      const fuseLogs = await sandbox.sh`grep -ri -E '(fuse|FUSE|Fuse)' /var/log/agentsh/ 2>&1 || echo "(no FUSE mentions found in log files)"`.noThrow().text();
      console.log(fuseLogs);
    } catch (err) {
      console.log(`Error searching logs: ${err}`);
    }

    subBanner("3c. Searching logs for Landlock-related messages");
    try {
      const landlockLogs = await sandbox.sh`grep -ri -E '(landlock|Landlock|LANDLOCK)' /var/log/agentsh/ 2>&1 || echo "(no Landlock mentions found in log files)"`.noThrow().text();
      console.log(landlockLogs);
    } catch (err) {
      console.log(`Error searching logs: ${err}`);
    }

    subBanner("3d. Searching logs for sandbox/security/degraded messages");
    try {
      const sandboxLogs = await sandbox.sh`grep -ri -E '(sandbox|security|degraded|seccomp|cgroup|enforce)' /var/log/agentsh/ 2>&1 || echo "(no sandbox-related mentions found)"`.noThrow().text();
      console.log(sandboxLogs);
    } catch (err) {
      console.log(`Error searching logs: ${err}`);
    }

    // Also check stderr from the server process (agentsh logs to stderr)
    subBanner("3e. Checking dmesg for FUSE/Landlock kernel messages");
    try {
      const dmesg = await sandbox.sh`dmesg 2>&1 | grep -iE '(fuse|landlock)' || echo "(no FUSE/Landlock messages in dmesg, or dmesg not available)"`.noThrow().text();
      console.log(dmesg);
    } catch (err) {
      console.log(`Error checking dmesg: ${err}`);
    }

    // =====================================================================
    // 4. Landlock enforcement test
    // =====================================================================
    banner("4. Landlock enforcement test");

    // Create a session so we can test file access through the exec API
    // (which goes through the shell shim and agentsh policy enforcement)
    console.log("Creating agentsh session for enforcement tests...");
    const sessionText = await sandbox.sh`agentsh session create --workspace /app --json`.text();
    const sessionOutput: SessionCreateResponse = JSON.parse(sessionText.trim());
    const sessionId: string = sessionOutput.id;
    console.log(`Session ID: ${sessionId}`);

    // Brief pause to let the server fully initialize the session
    await new Promise((r) => setTimeout(r, 1500));

    const apiBase = "http://127.0.0.1:18080";

    // Helper to run a command through the agentsh exec API
    async function execViaApi(
      command: string,
      args: string[],
    ): Promise<{ exitCode: number; stdout: string; stderr: string; blocked: boolean; policyRule: string }> {
      const payload = JSON.stringify({ command, args });
      const escapedPayload = payload.replace(/'/g, "'\\''");

      await sandbox.fs.writeTextFile(
        "/tmp/exec-cmd.sh",
        `#!/bin/sh
rm -f /tmp/exec-result.json
curl -s -X POST "${apiBase}/api/v1/sessions/${sessionId}/exec" \
  -H "Content-Type: application/json" \
  --connect-timeout 10 \
  --max-time 30 \
  -d '${escapedPayload}' \
  -o /tmp/exec-result.json 2>/dev/null
`,
      );

      await sandbox.sh`/bin/sh /tmp/exec-cmd.sh`.noThrow().result();

      let output: string;
      try {
        output = await sandbox.fs.readTextFile("/tmp/exec-result.json");
      } catch {
        return { exitCode: -1, stdout: "", stderr: "no API response", blocked: false, policyRule: "" };
      }

      try {
        const json: ExecResponse = JSON.parse(output.trim());

        if (json.result?.error?.code === "E_POLICY_DENIED") {
          const rule = json.result.error.policy_rule ?? "unknown";
          return { exitCode: -1, stdout: "", stderr: json.result.error.message ?? "", blocked: true, policyRule: rule };
        }

        if (json.guidance?.blocked || json.guidance?.status === "blocked") {
          const rule = json.guidance?.policy_rule ?? "unknown";
          return { exitCode: -1, stdout: "", stderr: json.guidance?.reason ?? "", blocked: true, policyRule: rule };
        }

        const exitCode = json.result?.exit_code ?? -1;
        const stdout = json.result?.stdout?.trim() ?? "";
        const stderr = json.result?.stderr?.trim() ?? "";
        return { exitCode, stdout, stderr, blocked: false, policyRule: "" };
      } catch {
        return { exitCode: -1, stdout: "", stderr: `parse error: ${output.slice(0, 200)}`, blocked: false, policyRule: "" };
      }
    }

    // -- 4a. Read /etc/shadow via exec API (should be DENIED by policy) --
    subBanner("4a. Read /etc/shadow via agentsh exec API (should be DENIED)");
    {
      const result = await execViaApi("/bin/cat", ["/etc/shadow"]);
      if (result.blocked) {
        console.log(`  BLOCKED by policy: ${result.policyRule}`);
        console.log("  -> Landlock/policy enforcement is WORKING for /etc/shadow");
      } else if (result.exitCode !== 0) {
        console.log(`  Command failed (exit ${result.exitCode}): ${result.stderr.slice(0, 200)}`);
        console.log("  -> File access was denied (may be OS-level or Landlock)");
      } else {
        console.log(`  WARNING: /etc/shadow was readable! stdout length: ${result.stdout.length}`);
        console.log("  -> Landlock may NOT be enforcing file restrictions");
      }
    }

    // -- 4b. Read /etc/shadow directly (bypassing agentsh shim) --
    subBanner("4b. Read /etc/shadow DIRECTLY (bypassing shim, via sandbox.sh)");
    try {
      const directResult = await sandbox.sh`/bin/sh -c 'cat /etc/shadow 2>&1'`.noThrow().text();
      if (directResult.includes("Permission denied") || directResult.includes("No such file")) {
        console.log(`  Direct read denied: ${directResult.trim()}`);
        console.log("  -> OS/Landlock-level protection is in effect");
      } else if (directResult.trim().length === 0) {
        console.log("  Direct read returned empty (file may not exist or is empty)");
      } else {
        console.log(`  WARNING: /etc/shadow was directly readable! (${directResult.length} bytes)`);
        console.log("  -> Landlock is NOT enforcing at the kernel level");
      }
    } catch (err) {
      console.log(`  Direct read threw error: ${err}`);
      console.log("  -> Access was denied");
    }

    // -- 4c. Read /etc/passwd via exec API (also should be denied by policy) --
    subBanner("4c. Read /etc/passwd via agentsh exec API (should be DENIED by default-deny-files)");
    {
      const result = await execViaApi("/bin/cat", ["/etc/passwd"]);
      if (result.blocked) {
        console.log(`  BLOCKED by policy: ${result.policyRule}`);
        console.log("  -> Policy enforcement is WORKING for /etc/passwd");
      } else if (result.exitCode !== 0) {
        console.log(`  Command failed (exit ${result.exitCode}): ${result.stderr.slice(0, 200)}`);
        console.log("  -> File access was denied");
      } else {
        console.log(`  /etc/passwd was readable (${result.stdout.split("\n").length} lines)`);
        console.log("  -> Policy may allow /etc/passwd or Landlock is not restricting it");
        console.log(`  First 3 lines: ${result.stdout.split("\n").slice(0, 3).join(" | ")}`);
      }
    }

    // -- 4d. Read /etc/passwd directly (bypassing shim) --
    subBanner("4d. Read /etc/passwd DIRECTLY (bypassing shim)");
    try {
      const directPasswd = await sandbox.sh`/bin/sh -c 'cat /etc/passwd 2>&1'`.noThrow().text();
      const lines = directPasswd.trim().split("\n");
      console.log(`  Direct read returned ${lines.length} lines`);
      console.log(`  First 3 lines: ${lines.slice(0, 3).join(" | ")}`);
      console.log("  -> Compare with exec API result above to see if policy adds restrictions");
    } catch (err) {
      console.log(`  Direct read threw error: ${err}`);
    }

    // -- 4e. Read /root/.ssh (should be approval-required or denied) --
    subBanner("4e. Read /root/.ssh/ via agentsh exec API (should be APPROVE or DENY)");
    {
      const result = await execViaApi("/bin/ls", ["-la", "/root/.ssh/"]);
      if (result.blocked) {
        console.log(`  BLOCKED by policy: ${result.policyRule}`);
        console.log("  -> Credential path protection is WORKING");
      } else if (result.exitCode !== 0) {
        console.log(`  Command failed (exit ${result.exitCode}): ${result.stderr.slice(0, 200)}`);
      } else {
        console.log(`  WARNING: /root/.ssh/ was listed: ${result.stdout.slice(0, 200)}`);
      }
    }

    // -- 4f. Write to a denied path --
    subBanner("4f. Write to /etc/test-write via agentsh exec API (should be DENIED)");
    {
      const result = await execViaApi("/bin/sh", ["-c", "echo test > /etc/test-write"]);
      if (result.blocked) {
        console.log(`  BLOCKED by policy: ${result.policyRule}`);
        console.log("  -> Write protection is WORKING");
      } else if (result.exitCode !== 0) {
        console.log(`  Command failed (exit ${result.exitCode}): ${result.stderr.slice(0, 200)}`);
        console.log("  -> Write was denied (OS-level or policy)");
      } else {
        console.log("  WARNING: write to /etc/ succeeded!");
        console.log("  -> Policy is NOT blocking writes to system paths");
      }
    }

    // -- 4g. Write to workspace (should be ALLOWED) --
    subBanner("4g. Write to /app/test-allowed.txt via exec API (should be ALLOWED)");
    {
      const result = await execViaApi("/bin/sh", ["-c", "echo 'sandbox test' > /app/test-allowed.txt && cat /app/test-allowed.txt"]);
      if (result.blocked) {
        console.log(`  BLOCKED by policy: ${result.policyRule}`);
        console.log("  -> Unexpected: workspace writes should be allowed");
      } else if (result.exitCode === 0) {
        console.log(`  Success: ${result.stdout}`);
        console.log("  -> Workspace write is correctly ALLOWED");
      } else {
        console.log(`  Failed (exit ${result.exitCode}): ${result.stderr.slice(0, 200)}`);
      }
    }

    // =====================================================================
    // 5. FUSE mount check
    // =====================================================================
    banner("5. FUSE mount check");

    subBanner("5a. Check /proc/mounts for fuse");
    try {
      const procMounts = await sandbox.sh`grep -i fuse /proc/mounts 2>&1 || echo "(no FUSE mounts found in /proc/mounts)"`.noThrow().text();
      console.log(procMounts);
    } catch (err) {
      console.log(`Error checking /proc/mounts: ${err}`);
    }

    subBanner("5b. mount | grep fuse");
    try {
      const mountGrep = await sandbox.sh`mount 2>&1 | grep -i fuse || echo "(no FUSE mounts found via mount command)"`.noThrow().text();
      console.log(mountGrep);
    } catch (err) {
      console.log(`Error running mount: ${err}`);
    }

    subBanner("5c. Check /proc/filesystems for fuse support");
    try {
      const fsTypes = await sandbox.sh`grep -i fuse /proc/filesystems 2>&1 || echo "(FUSE not listed in /proc/filesystems)"`.noThrow().text();
      console.log(fsTypes);
    } catch (err) {
      console.log(`Error checking /proc/filesystems: ${err}`);
    }

    subBanner("5d. Check /dev/fuse device");
    try {
      const devFuse = await sandbox.sh`ls -la /dev/fuse 2>&1 || echo "(/dev/fuse does not exist)"`.noThrow().text();
      console.log(devFuse);
    } catch (err) {
      console.log(`Error checking /dev/fuse: ${err}`);
    }

    subBanner("5e. Check if fusermount is available");
    try {
      const fusermount = await sandbox.sh`which fusermount 2>&1 || which fusermount3 2>&1 || echo "(fusermount not found)"`.noThrow().text();
      console.log(fusermount);
    } catch (err) {
      console.log(`Error checking fusermount: ${err}`);
    }

    // =====================================================================
    // 6. Additional kernel feature checks
    // =====================================================================
    banner("6. Additional kernel feature checks");

    subBanner("6a. Kernel version");
    try {
      const uname = await sandbox.sh`uname -a 2>&1`.noThrow().text();
      console.log(uname);
    } catch (err) {
      console.log(`Error: ${err}`);
    }

    subBanner("6b. Landlock ABI version (/sys/kernel/security/landlock/abi_version)");
    try {
      const landlockAbi = await sandbox.sh`cat /sys/kernel/security/landlock/abi_version 2>&1 || echo "(not available -- Landlock may not be enabled in kernel)"`.noThrow().text();
      console.log(`  Landlock ABI version: ${landlockAbi.trim()}`);
    } catch (err) {
      console.log(`Error: ${err}`);
    }

    subBanner("6c. Seccomp status");
    try {
      const seccomp = await sandbox.sh`grep -i seccomp /proc/self/status 2>&1 || echo "(seccomp info not available)"`.noThrow().text();
      console.log(seccomp);
    } catch (err) {
      console.log(`Error: ${err}`);
    }

    subBanner("6d. Cgroups");
    try {
      const cgroups = await sandbox.sh`cat /proc/self/cgroup 2>&1 || echo "(cgroup info not available)"`.noThrow().text();
      console.log(cgroups);
    } catch (err) {
      console.log(`Error: ${err}`);
    }

    subBanner("6e. Capabilities");
    try {
      const caps = await sandbox.sh`grep -i cap /proc/self/status 2>&1 || echo "(capability info not available)"`.noThrow().text();
      console.log(caps);
    } catch (err) {
      console.log(`Error: ${err}`);
    }

    subBanner("6f. agentsh server status (health check)");
    try {
      const health = await sandbox.sh`curl -s http://127.0.0.1:18080/health 2>&1`.noThrow().text();
      console.log(`  Health: ${health.trim()}`);
    } catch (err) {
      console.log(`Error: ${err}`);
    }

    // =====================================================================
    // Summary
    // =====================================================================
    banner("DIAGNOSTIC COMPLETE");
    console.log(`
Review the output above to determine:
  - Whether agentsh detects FUSE and Landlock as available
  - Whether FUSE is actually mounted (section 5)
  - Whether Landlock enforcement is active (section 4: denied paths vs allowed)
  - Whether the policy layer (agentsh exec API) adds file restrictions
    even if Landlock is not available at the kernel level
`);

  } finally {
    console.log("Cleaning up sandbox...");
    await sandbox.close();
    console.log("Sandbox closed.");
  }
}

main();
