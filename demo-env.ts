/**
 * demo-env.ts — Demonstrates agentsh environment variable policy enforcement
 * inside a Deno Sandbox.
 *
 * Exercises the env_policy defined in default.yaml:
 *   - Allowed vars (PATH, HOME, USER)        -> visible to commands
 *   - Denied vars (AWS_*, OPENAI_API_KEY)     -> hidden from commands
 *   - Vars not in allow list                  -> hidden from commands
 *   - Env enumeration (printenv, env)         -> blocked by block_iteration
 *
 * Injects test "secret" env vars into the sandbox before starting the agentsh
 * server, then verifies the exec API filters them per the env_policy.
 *
 * Uses the agentsh HTTP exec API directly (POST /api/v1/sessions/:id/exec)
 * to avoid shell shim interference with the agentsh CLI.
 *
 * Usage:
 *   deno run --allow-all --env-file=.env demo-env.ts
 */

import { createAgentshSandbox } from "./setup.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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
  console.log("=== agentsh Environment Policy Demo ===\n");

  // Inject "secret" env vars that should be blocked by env_policy deny rules.
  // These are set before the agentsh server starts so it inherits them, but
  // the env_policy should prevent exec'd commands from seeing them.
  const sandbox = await createAgentshSandbox({
    envVars: {
      AWS_SECRET_ACCESS_KEY: "AKIAIOSFODNN7EXAMPLE",
      AWS_SESSION_TOKEN: "FwoGZXIvY...test-token",
      OPENAI_API_KEY: "sk-test-openai-key-67890",
      DATABASE_URL: "postgresql://admin:s3cret@db.internal:5432/prod",
      SECRET_SIGNING_KEY: "hmac-sha256-test-key",
      MY_CUSTOM_SETTING: "this-is-not-in-allow-list",
    },
  });

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
    ): Promise<{ exitCode: number; stdout: string; stderr: string; blocked: boolean }> {
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
        return { exitCode: -1, stdout: "", stderr: "", blocked: false };
      }

      try {
        const json: ExecResponse = JSON.parse(output.trim());

        // Explicit policy denial
        if (json.result?.error?.code === "E_POLICY_DENIED") {
          const rule = json.result.error.policy_rule ?? "unknown";
          console.log(`         BLOCKED by policy rule: ${rule}`);
          return { exitCode: -1, stdout: "", stderr: "", blocked: true };
        }

        // Blocked operations in events
        const blockedOps = json.events?.blocked_operations ?? [];
        if (blockedOps.length > 0) {
          const first = blockedOps[0];
          const rule = first.policy?.rule ?? "unknown";
          console.log(`         BLOCKED by policy: ${rule}`);
          return { exitCode: -1, stdout: "", stderr: "", blocked: true };
        }

        // Guidance says blocked
        if (json.guidance?.blocked || json.guidance?.status === "blocked") {
          const rule = json.guidance?.policy_rule ?? "unknown";
          console.log(`         BLOCKED: ${rule}`);
          return { exitCode: -1, stdout: "", stderr: "", blocked: true };
        }

        const exitCode = json.result?.exit_code ?? -1;
        const stdout = json.result?.stdout?.trim() ?? "";
        const stderr = json.result?.stderr?.trim() ?? "";
        return { exitCode, stdout, stderr, blocked: false };
      } catch {
        console.log(`         ERROR: failed to parse response: ${output.slice(0, 200)}`);
        return { exitCode: -1, stdout: "", stderr: "", blocked: false };
      }
    }

    // =======================================================================
    // Test: ALLOWED ENV VARS — should be visible
    // =======================================================================
    console.log("\n--- ALLOWED: Standard env vars (in allow list) ---\n");

    for (const varName of ["PATH", "HOME", "TERM"]) {
      const result = await runAgentsh(
        `Read ${varName} (should be VISIBLE)`,
        "/usr/bin/printenv",
        [varName],
      );
      if (result.blocked) {
        console.log(`         -> ${varName}: BLOCKED (unexpected)\n`);
      } else if (result.exitCode === 0 && result.stdout) {
        console.log(`         -> ${varName}=${result.stdout.slice(0, 80)}`);
        console.log(`         PASS: env var is visible\n`);
      } else {
        console.log(`         -> ${varName}: empty or not set (exit ${result.exitCode})`);
        console.log(`         NOTE: var may not be set in sandbox env\n`);
      }
    }

    // =======================================================================
    // Test: DENIED ENV VARS — should be hidden even though they were set
    // =======================================================================
    console.log("--- DENIED: Secret env vars (in deny list) ---\n");

    const deniedVars = [
      ["AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"],
      ["AWS_SESSION_TOKEN", "FwoGZXIvY...test-token"],
      ["OPENAI_API_KEY", "sk-test-openai-key-67890"],
      ["DATABASE_URL", "postgresql://admin:s3cret@db.internal:5432/prod"],
      ["SECRET_SIGNING_KEY", "hmac-sha256-test-key"],
    ];

    for (const [varName, expectedValue] of deniedVars) {
      const result = await runAgentsh(
        `Read ${varName} (should be HIDDEN)`,
        "/usr/bin/printenv",
        [varName],
      );
      if (result.blocked) {
        console.log(`         -> ${varName}: BLOCKED by policy`);
        console.log(`         PASS: secret is protected\n`);
      } else if (result.exitCode !== 0 || !result.stdout) {
        console.log(`         -> ${varName}: not visible (exit ${result.exitCode})`);
        console.log(`         PASS: secret is hidden from commands\n`);
      } else if (result.stdout === expectedValue) {
        console.log(`         -> ${varName}=${result.stdout.slice(0, 30)}...`);
        console.log(`         FAIL: secret is EXPOSED to commands!\n`);
      } else {
        console.log(`         -> ${varName}=${result.stdout.slice(0, 30)}`);
        console.log(`         UNEXPECTED: different value returned\n`);
      }
    }

    // =======================================================================
    // Test: NOT IN ALLOW LIST — should be hidden
    // =======================================================================
    console.log("--- NOT IN ALLOW LIST: Custom env var ---\n");

    {
      const result = await runAgentsh(
        "Read MY_CUSTOM_SETTING (not in allow list, should be HIDDEN)",
        "/usr/bin/printenv",
        ["MY_CUSTOM_SETTING"],
      );
      if (result.blocked) {
        console.log("         -> BLOCKED by policy");
        console.log("         PASS: unlisted var is protected\n");
      } else if (result.exitCode !== 0 || !result.stdout) {
        console.log(`         -> not visible (exit ${result.exitCode})`);
        console.log("         PASS: unlisted var is hidden\n");
      } else {
        console.log(`         -> MY_CUSTOM_SETTING=${result.stdout.slice(0, 50)}`);
        console.log("         FAIL: unlisted var is EXPOSED\n");
      }
    }

    // =======================================================================
    // Test: ENV ENUMERATION — should be blocked or filtered
    // =======================================================================
    console.log("--- ENUMERATION: List all env vars (block_iteration) ---\n");

    {
      const result = await runAgentsh(
        "printenv (list all — should be BLOCKED or filtered)",
        "/usr/bin/printenv",
        [],
      );
      if (result.blocked) {
        console.log("         -> BLOCKED: enumeration prevented");
        console.log("         PASS: block_iteration enforced\n");
      } else if (result.exitCode === 0 && result.stdout) {
        // Check if secrets leaked
        const lines = result.stdout.split("\n");
        const hasSecret = lines.some((l: string) =>
          l.startsWith("AWS_") ||
          l.startsWith("OPENAI_") ||
          l.startsWith("DATABASE_URL") ||
          l.startsWith("SECRET_")
        );
        console.log(`         -> returned ${lines.length} env var(s)`);
        if (hasSecret) {
          console.log("         FAIL: secrets visible in enumeration!\n");
        } else {
          console.log("         PASS: enumeration filtered (no secrets leaked)\n");
        }
        // Show first few vars for reference
        console.log("         Visible vars:");
        for (const line of lines.slice(0, 10)) {
          const eqIdx = line.indexOf("=");
          if (eqIdx > 0) {
            const key = line.substring(0, eqIdx);
            const val = line.substring(eqIdx + 1).slice(0, 40);
            console.log(`           ${key}=${val}`);
          }
        }
        if (lines.length > 10) {
          console.log(`           ... and ${lines.length - 10} more`);
        }
        console.log();
      } else {
        console.log(`         -> empty or failed (exit ${result.exitCode})`);
        console.log("         NOTE: enumeration returned nothing\n");
      }
    }

    // Also test with `env` command
    {
      const result = await runAgentsh(
        "env (list all — should be BLOCKED or filtered)",
        "/usr/bin/env",
        [],
      );
      if (result.blocked) {
        console.log("         -> BLOCKED: enumeration prevented");
        console.log("         PASS: block_iteration enforced\n");
      } else if (result.exitCode === 0 && result.stdout) {
        const lines = result.stdout.split("\n");
        const hasSecret = lines.some((l: string) =>
          l.startsWith("AWS_") ||
          l.startsWith("OPENAI_") ||
          l.startsWith("DATABASE_URL") ||
          l.startsWith("SECRET_")
        );
        console.log(`         -> returned ${lines.length} env var(s)`);
        if (hasSecret) {
          console.log("         FAIL: secrets visible in enumeration!\n");
        } else {
          console.log("         PASS: enumeration filtered (no secrets leaked)\n");
        }
      } else {
        console.log(`         -> empty or failed (exit ${result.exitCode})`);
        console.log("         NOTE: enumeration returned nothing\n");
      }
    }

    // =======================================================================
    console.log("=== ENVIRONMENT DEMO COMPLETE ===");
  } finally {
    console.log("\nCleaning up sandbox...");
    await sandbox.close();
    console.log("Sandbox closed.");
  }
}

main();
