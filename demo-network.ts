/**
 * demo-network.ts — Demonstrates agentsh network policy enforcement inside a
 * Deno Sandbox.
 *
 * Exercises the network_rules defined in default.yaml:
 *   - Localhost connections     -> allowed
 *   - Cloud metadata IPs       -> blocked (CIDR 169.254.0.0/16)
 *   - Private network CIDRs    -> blocked (10.x, 172.16.x, 192.168.x)
 *   - Package registries       -> allowed (npmjs.org, pypi.org)
 *
 * Uses the agentsh HTTP exec API directly (POST /api/v1/sessions/:id/exec)
 * to avoid shell shim interference with the agentsh CLI.
 *
 * Usage:
 *   deno run --allow-all --env-file=.env demo-network.ts
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
      policy?: {
        rule?: string;
        message?: string;
      };
    }>;
    blocked_operations_count?: number;
  };
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
      await sandbox.sh`agentsh session create --workspace /app --json`.text();
    const sessionData: SessionCreateResponse = JSON.parse(
      sessionOutput.trim(),
    );
    const sessionId: string = sessionData.id;
    console.log(`Session ID: ${sessionId}\n`);

    // Brief pause to let the server fully initialize the session
    await new Promise((r) => setTimeout(r, 1500));

    // -----------------------------------------------------------------------
    // Helper: run a command through the agentsh exec HTTP API
    // -----------------------------------------------------------------------
    const apiBase = "http://127.0.0.1:18080";

    async function runAgentsh(
      description: string,
      command: string,
      args: string[],
    ): Promise<RunResult> {
      console.log(`  [TEST] ${description}`);
      console.log(`         command: ${command} ${args.join(" ")}`);

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
        console.log("         ERROR: no response from API");
        return { allowed: false, output: "" };
      }

      try {
        const json: ExecResponse = JSON.parse(output.trim());

        // Check 1: Explicit command policy denial
        if (json.result?.error?.code === "E_POLICY_DENIED") {
          const rule = json.result.error.policy_rule ?? "unknown";
          console.log(`         BLOCKED by policy rule: ${rule}`);
          return { allowed: false, output };
        }

        // Check 2: Network operations blocked (reported in events)
        const blockedOps = json.events?.blocked_operations ?? [];
        if (blockedOps.length > 0) {
          const first = blockedOps[0];
          const rule = first.policy?.rule ?? "unknown";
          const msg = first.policy?.message ?? "";
          console.log(
            `         BLOCKED by network policy: ${rule}${msg ? ` — ${msg}` : ""}`,
          );
          return { allowed: false, output };
        }

        // Check 3: Guidance indicates blocked
        if (json.guidance?.blocked || json.guidance?.status === "blocked") {
          const rule = json.guidance?.policy_rule ?? "unknown";
          const reason = json.guidance?.reason ?? "";
          console.log(
            `         BLOCKED: ${rule}${reason ? ` — ${reason}` : ""}`,
          );
          return { allowed: false, output };
        }

        // Check 4: Command succeeded
        if (json.result?.exit_code === 0) {
          const stdout = json.result?.stdout?.trim() ?? "";
          const preview = stdout.substring(0, 150).replace(/\n/g, "\\n");
          console.log(`         ALLOWED (exit 0): ${preview}`);
          return { allowed: true, output: stdout };
        }

        // Check 5: Non-zero exit — for curl, this means the connection was
        // blocked at network level (iptables/nftables deny)
        const exitCode = json.result?.exit_code ?? -1;
        const stderr = json.result?.stderr?.trim() ?? "";
        console.log(
          `         BLOCKED (network-level, exit ${exitCode}): ${stderr.slice(0, 100) || "connection failed"}`,
        );
        return { allowed: false, output };
      } catch {
        console.log(`         ERROR: failed to parse response: ${output.slice(0, 200)}`);
        return { allowed: false, output };
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
    // Test: MORE PRIVATE NETWORKS BLOCKED
    // =======================================================================
    console.log("\n--- MORE PRIVATE NETWORKS BLOCKED ---\n");

    await runAgentsh(
      "Private network 172.16.x (should be BLOCKED)",
      "/usr/bin/curl",
      ["-s", "--connect-timeout", "3", "http://172.16.0.1/"],
    );

    await runAgentsh(
      "Cloud metadata 169.254.169.254 via CIDR (should be BLOCKED)",
      "/usr/bin/curl",
      ["-s", "--connect-timeout", "3", "http://169.254.169.254/latest/meta-data/"],
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
