/**
 * demo-blocking.ts — Demonstrates agentsh command policy enforcement inside
 * a Deno Sandbox.
 *
 * Creates a sandbox with agentsh installed, starts a session, and exercises
 * various command categories to show which are allowed and which are blocked
 * by the default security policy.
 *
 * Uses the agentsh HTTP exec API directly (POST /api/v1/sessions/:id/exec)
 * to avoid shell shim interference with the agentsh CLI.
 */

import { createAgentshSandbox } from "./setup.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SessionCreateOutput {
  id: string;
}

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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const sandbox = await createAgentshSandbox();

  try {
    // -----------------------------------------------------------------------
    // 1. Create an agentsh session
    // -----------------------------------------------------------------------
    console.log("\n=== Creating agentsh session ===\n");
    const sessionText = await sandbox.sh`agentsh session create --workspace /app --json`.text();
    const sessionOutput: SessionCreateOutput = JSON.parse(sessionText.trim());
    const sessionId: string = sessionOutput.id;
    console.log(`Session ID: ${sessionId}`);

    // Brief pause to let the server fully initialize the session
    await new Promise((r) => setTimeout(r, 1500));

    // -----------------------------------------------------------------------
    // 2. Helper to run a command via the agentsh exec HTTP API
    // -----------------------------------------------------------------------
    const apiBase = "http://127.0.0.1:18080";

    async function runAgentsh(
      description: string,
      command: string,
      args: string[],
    ): Promise<void> {
      console.log(`  ${description}: ${command} ${args.join(" ")}`);

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
        console.log("    -> ERROR: no response from API");
        return;
      }

      try {
        const json: ExecResponse = JSON.parse(output.trim());

        if (json.result?.error?.code === "E_POLICY_DENIED") {
          const rule = json.result.error.policy_rule ?? "unknown";
          console.log(`    -> BLOCKED by policy rule: ${rule}`);
        } else if (json.result?.exit_code === 0) {
          const stdout = json.result?.stdout?.trim();
          const detail = stdout ? ` (output: ${stdout.slice(0, 80)})` : "";
          console.log(`    -> ALLOWED (exit: 0)${detail}`);
        } else {
          const reason = json.result?.stderr?.trim() ??
            json.guidance?.reason ?? "unknown error";
          console.log(
            `    -> ALLOWED (exit: ${json.result?.exit_code ?? "?"}): ${reason.slice(0, 100)}`,
          );
        }
      } catch {
        console.log(`    -> ERROR: failed to parse response: ${output.slice(0, 200)}`);
      }
    }

    // -----------------------------------------------------------------------
    // 3. ALLOWED — Safe commands
    // -----------------------------------------------------------------------
    console.log("\n=== ALLOWED: Safe Commands ===\n");
    await runAgentsh("Echo", "/bin/echo", ["Hello"]);
    await runAgentsh("Print working directory", "/bin/pwd", []);
    await runAgentsh("List directory", "/bin/ls", ["/tmp"]);
    await runAgentsh("Date", "/bin/date", []);

    // -----------------------------------------------------------------------
    // 4. BLOCKED — Privilege escalation
    // -----------------------------------------------------------------------
    console.log("\n=== BLOCKED: Privilege Escalation ===\n");
    await runAgentsh("Sudo", "sudo", ["whoami"]);
    await runAgentsh("Su", "su", ["-"]);
    await runAgentsh("Chroot", "chroot", ["/"]);

    // -----------------------------------------------------------------------
    // 5. BLOCKED — Network tools
    // -----------------------------------------------------------------------
    console.log("\n=== BLOCKED: Network Tools ===\n");
    await runAgentsh("SSH", "ssh", ["localhost"]);
    await runAgentsh("Netcat", "nc", ["-h"]);

    // -----------------------------------------------------------------------
    // 6. BLOCKED — System commands
    // -----------------------------------------------------------------------
    console.log("\n=== BLOCKED: System Commands ===\n");
    await runAgentsh("Kill", "kill", ["-9", "1"]);
    await runAgentsh("Shutdown", "shutdown", ["now"]);
    await runAgentsh("Systemctl", "systemctl", ["status"]);

    // -----------------------------------------------------------------------
    // 7. BLOCKED — Recursive delete
    // -----------------------------------------------------------------------
    console.log("\n=== BLOCKED: Recursive Delete ===\n");

    // Create a test directory with a file
    await sandbox.sh`mkdir -p /tmp/test && touch /tmp/test/file.txt`;
    console.log("  (created /tmp/test/file.txt for testing)");

    await runAgentsh("rm -rf (force recursive)", "rm", ["-rf", "/tmp/test"]);
    await runAgentsh("rm -r (recursive)", "rm", ["-r", "/tmp/test"]);

    // -----------------------------------------------------------------------
    // 8. ALLOWED — Single file delete
    // -----------------------------------------------------------------------
    console.log("\n=== ALLOWED: Single File Delete ===\n");

    // Recreate the test directory in case it was removed
    await sandbox.sh`mkdir -p /tmp/test && touch /tmp/test/file.txt`;
    console.log("  (recreated /tmp/test/file.txt for testing)");

    await runAgentsh("rm single file", "/bin/rm", ["/tmp/test/file.txt"]);

    // -----------------------------------------------------------------------
    // Done
    // -----------------------------------------------------------------------
    console.log("\nDEMO COMPLETE");
  } finally {
    await sandbox.close();
    console.log("Sandbox closed.");
  }
}

main();
