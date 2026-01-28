/**
 * demo-network.ts — Demonstrates agentsh network policy enforcement inside a
 * Deno Sandbox.
 *
 * Exercises the network_rules defined in default.yaml:
 *   - Localhost connections   -> allowed
 *   - Cloud metadata IPs     -> blocked
 *   - Private network CIDRs  -> blocked
 *   - Package registries     -> allowed
 *   - Unknown/other domains  -> blocked (default deny)
 *
 * Usage:
 *   deno run --allow-net --allow-env --allow-read demo-network.ts
 */

import { createAgentshSandbox } from "./setup.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RunResult {
  allowed: boolean;
  output: string;
}

interface SessionCreateResponse {
  id: string;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("=== agentsh Network Policy Demo ===\n");

  const sandbox = await createAgentshSandbox();

  try {
    // -----------------------------------------------------------------------
    // Create a session
    // -----------------------------------------------------------------------
    console.log("Creating agentsh session...");
    const sessionOutput =
      await sandbox.sh`agentsh session create --workspace /home/user --json`.text();
    const sessionData: SessionCreateResponse = JSON.parse(
      sessionOutput.trim(),
    );
    const sessionId: string = sessionData.id;
    console.log(`Session ID: ${sessionId}\n`);

    // -----------------------------------------------------------------------
    // Helper: run a command through agentsh exec and report result
    // -----------------------------------------------------------------------
    async function runAgentsh(
      description: string,
      command: string,
      args: string[],
    ): Promise<RunResult> {
      console.log(`  [TEST] ${description}`);
      console.log(`         command: ${command} ${args.join(" ")}`);

      const payload = JSON.stringify({ command, args });

      try {
        const result =
          await sandbox.sh`agentsh exec ${sessionId} --json ${payload} 2>&1`.result();
        const output: string = result.stdoutText ?? "";
        const exitCode: number = result.status.code;
        const preview = output.substring(0, 150).replace(/\n/g, "\\n");
        console.log(`         ALLOWED (exit ${exitCode}): ${preview}`);
        return { allowed: true, output };
      } catch (err: unknown) {
        const message: string =
          err instanceof Error ? err.message : String(err);
        const policyMatch = message.match(/denied by policy(?:\s*\[([^\]]+)\])?/i);
        if (policyMatch) {
          const ruleName = policyMatch[1] ?? "unknown rule";
          console.log(`         BLOCKED by policy rule: ${ruleName}`);
        } else {
          console.log(
            `         BLOCKED: ${message.substring(0, 150)}`,
          );
        }
        return { allowed: false, output: message };
      }
    }

    // =======================================================================
    // Test: LOCALHOST ALLOWED
    // =======================================================================
    console.log("\n--- LOCALHOST ALLOWED ---\n");

    await runAgentsh(
      "Localhost health check (should be ALLOWED)",
      "/usr/bin/curl",
      ["-s", "-w", "\\nHTTP_CODE:%{http_code}", "http://127.0.0.1:18080/health"],
    );

    // =======================================================================
    // Test: CLOUD METADATA BLOCKED
    // =======================================================================
    console.log("\n--- CLOUD METADATA BLOCKED ---\n");

    await runAgentsh(
      "AWS metadata service (should be BLOCKED)",
      "/usr/bin/curl",
      [
        "-s",
        "-w",
        "\\nHTTP_CODE:%{http_code}",
        "--connect-timeout",
        "5",
        "http://169.254.169.254/",
      ],
    );

    // =======================================================================
    // Test: PRIVATE NETWORKS BLOCKED
    // =======================================================================
    console.log("\n--- PRIVATE NETWORKS BLOCKED ---\n");

    await runAgentsh(
      "Private network 10.x (should be BLOCKED)",
      "/usr/bin/curl",
      ["-s", "--connect-timeout", "3", "http://10.0.0.1/"],
    );

    await runAgentsh(
      "Private network 192.168.x (should be BLOCKED)",
      "/usr/bin/curl",
      ["-s", "--connect-timeout", "3", "http://192.168.1.1/"],
    );

    // =======================================================================
    // Test: PACKAGE REGISTRIES ALLOWED
    // =======================================================================
    console.log("\n--- PACKAGE REGISTRIES ALLOWED ---\n");

    await runAgentsh(
      "npm registry (should be ALLOWED)",
      "/usr/bin/curl",
      [
        "-s",
        "-w",
        "\\nHTTP_CODE:%{http_code}",
        "--connect-timeout",
        "10",
        "-o",
        "/dev/null",
        "https://registry.npmjs.org/",
      ],
    );

    await runAgentsh(
      "PyPI (should be ALLOWED)",
      "/usr/bin/curl",
      [
        "-s",
        "-w",
        "\\nHTTP_CODE:%{http_code}",
        "--connect-timeout",
        "10",
        "-o",
        "/dev/null",
        "https://pypi.org/",
      ],
    );

    // =======================================================================
    // Test: UNKNOWN DOMAINS BLOCKED
    // =======================================================================
    console.log("\n--- UNKNOWN DOMAINS BLOCKED ---\n");

    await runAgentsh(
      "example.com (should be BLOCKED by default deny)",
      "/usr/bin/curl",
      [
        "-s",
        "--connect-timeout",
        "5",
        "-o",
        "/dev/null",
        "https://example.com/",
      ],
    );

    // =======================================================================
    console.log("\n=== NETWORK DEMO COMPLETE ===");
  } finally {
    console.log("\nCleaning up sandbox...");
    await sandbox.close();
    console.log("Sandbox closed.");
  }
}

main();
