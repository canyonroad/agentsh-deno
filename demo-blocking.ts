/**
 * demo-blocking.ts — Demonstrates agentsh command policy enforcement inside
 * a Deno Sandbox.
 *
 * Creates a sandbox with agentsh installed, starts a session, and exercises
 * various command categories to show which are allowed and which are blocked
 * by the default security policy.
 */

import { createAgentshSandbox } from "./setup.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SessionCreateOutput {
  id: string;
}

interface ShResult {
  stdout: string;
  stderr: string;
  code: number;
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
    const sessionResult = (await sandbox.sh`agentsh session create --workspace /home/user --json`) as unknown as ShResult;
    const sessionOutput: SessionCreateOutput = JSON.parse(sessionResult.stdout.trim());
    const sessionId: string = sessionOutput.id;
    console.log(`Session ID: ${sessionId}`);

    // -----------------------------------------------------------------------
    // 2. Helper to run a command via agentsh exec and report the outcome
    // -----------------------------------------------------------------------
    async function runAgentsh(
      description: string,
      command: string,
      args: string[],
    ): Promise<void> {
      const payload = JSON.stringify({ command, args });
      console.log(`  ${description}: ${command} ${args.join(" ")}`);
      try {
        const result = (await sandbox.sh`agentsh exec ${sessionId} --json ${payload} 2>&1`) as unknown as ShResult;
        console.log(`    -> ALLOWED (exit: ${result.code})`);
      } catch (err: unknown) {
        const error = err as { stdout?: string; stderr?: string; message?: string };
        const output = (error.stdout ?? "") + (error.stderr ?? "") + (error.message ?? "");
        if (output.includes("denied by policy")) {
          const ruleMatch = output.match(/rule[:\s]+"?([^"|\n]+)"?/i)
            ?? output.match(/policy rule[:\s]+"?([^"|\n]+)"?/i)
            ?? output.match(/"rule_name"[:\s]+"?([^"|\n]+)"?/i);
          const ruleName = ruleMatch ? ruleMatch[1].trim() : "unknown";
          console.log(`    -> BLOCKED by policy rule: ${ruleName}`);
        } else {
          console.log(`    -> BLOCKED (non-policy error): ${output.slice(0, 200)}`);
        }
      }
    }

    // -----------------------------------------------------------------------
    // 3. ALLOWED — Safe commands
    // -----------------------------------------------------------------------
    console.log("\n=== ALLOWED: Safe Commands ===\n");
    await runAgentsh("Echo", "/bin/echo", ["Hello"]);
    await runAgentsh("Print working directory", "/bin/pwd", []);
    await runAgentsh("List directory", "/bin/ls", ["/home"]);
    await runAgentsh("Date", "/bin/date", []);
    await runAgentsh("Python3 one-liner", "/usr/bin/python3", ["-c", "print(1)"]);
    await runAgentsh("Git version", "/usr/bin/git", ["--version"]);

    // -----------------------------------------------------------------------
    // 4. BLOCKED — Privilege escalation
    // -----------------------------------------------------------------------
    console.log("\n=== BLOCKED: Privilege Escalation ===\n");
    await runAgentsh("Sudo", "/usr/bin/sudo", ["whoami"]);
    await runAgentsh("Su", "/bin/su", ["-"]);
    await runAgentsh("Chroot", "/usr/sbin/chroot", ["/"]);

    // -----------------------------------------------------------------------
    // 5. BLOCKED — Network tools
    // -----------------------------------------------------------------------
    console.log("\n=== BLOCKED: Network Tools ===\n");
    await runAgentsh("SSH", "/usr/bin/ssh", ["localhost"]);
    await runAgentsh("Netcat", "/bin/nc", ["-h"]);

    // -----------------------------------------------------------------------
    // 6. BLOCKED — System commands
    // -----------------------------------------------------------------------
    console.log("\n=== BLOCKED: System Commands ===\n");
    await runAgentsh("Kill", "/bin/kill", ["-9", "1"]);
    await runAgentsh("Shutdown", "/sbin/shutdown", ["now"]);
    await runAgentsh("Systemctl", "/usr/bin/systemctl", ["status"]);

    // -----------------------------------------------------------------------
    // 7. BLOCKED — Recursive delete
    // -----------------------------------------------------------------------
    console.log("\n=== BLOCKED: Recursive Delete ===\n");

    // Create a test directory with a file
    await sandbox.sh`mkdir -p /tmp/test && touch /tmp/test/file.txt`;
    console.log("  (created /tmp/test/file.txt for testing)");

    await runAgentsh("rm -rf (force recursive)", "/bin/rm", ["-rf", "/tmp/test"]);
    await runAgentsh("rm -r (recursive)", "/bin/rm", ["-r", "/tmp/test"]);

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
