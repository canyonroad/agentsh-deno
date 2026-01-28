/**
 * test-sandbox.ts — Verification tests for the agentsh sandbox.
 *
 * Creates a sandbox via `createAgentshSandbox()`, then runs a series of
 * smoke tests to confirm that agentsh is installed, the server is healthy,
 * configuration files are in place, the shell shim is working, and sessions
 * can be created.
 *
 * Usage:
 *   deno run --allow-all test-sandbox.ts
 */

import { createAgentshSandbox } from "./setup.ts";
import type { Sandbox } from "@deno/sandbox";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function pass(name: string, detail?: string): void {
  passed++;
  const suffix = detail ? ` — ${detail}` : "";
  console.log(`  PASS: ${name}${suffix}`);
}

function fail(name: string, detail?: string): void {
  failed++;
  const suffix = detail ? ` — ${detail}` : "";
  console.error(`  FAIL: ${name}${suffix}`);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

async function runTests(sandbox: Sandbox): Promise<void> {
  // Test 1: agentsh installation
  {
    console.log("\n=== Test 1: agentsh installation ===");
    const result = await sandbox.sh`agentsh --version`;
    const stdout = result.stdout?.trim() ?? "";
    if (stdout.includes("agentsh")) {
      pass("agentsh installation", stdout);
    } else {
      fail("agentsh installation", `expected stdout to include "agentsh", got: ${stdout}`);
    }
  }

  // Test 2: server health
  {
    console.log("\n=== Test 2: server health ===");
    const result = await sandbox.sh`curl -s http://127.0.0.1:18080/health`;
    const stdout = result.stdout?.trim() ?? "";
    if (stdout === "ok") {
      pass("server health", stdout);
    } else {
      fail("server health", `expected "ok", got: ${stdout}`);
    }
  }

  // Test 3: policy file
  {
    console.log("\n=== Test 3: policy file ===");
    const result = await sandbox.sh`head -5 /etc/agentsh/policies/default.yaml`;
    const stdout = result.stdout ?? "";
    if (stdout.includes("version")) {
      pass("policy file", "contains 'version'");
    } else {
      fail("policy file", `expected to include "version", got: ${stdout}`);
    }
  }

  // Test 4: config file
  {
    console.log("\n=== Test 4: config file ===");
    const result = await sandbox.sh`head -5 /etc/agentsh/config.yaml`;
    const stdout = result.stdout ?? "";
    if (stdout.includes("server")) {
      pass("config file", "contains 'server'");
    } else {
      fail("config file", `expected to include "server", got: ${stdout}`);
    }
  }

  // Test 5: shell shim
  {
    console.log("\n=== Test 5: shell shim ===");
    const result = await sandbox.sh`file /bin/bash.real 2>/dev/null || echo "NOT_FOUND"`;
    const stdout = result.stdout ?? "";
    if (!stdout.includes("NOT_FOUND")) {
      pass("shell shim", "/bin/bash.real exists");
    } else {
      fail("shell shim", "/bin/bash.real not found — shim may not be installed");
    }
  }

  // Test 6: command through shim
  {
    console.log("\n=== Test 6: command through shim ===");
    const result = await sandbox.sh`/bin/bash -c "echo hello_from_shim"`;
    const stdout = result.stdout?.trim() ?? "";
    if (stdout.includes("hello_from_shim")) {
      pass("command through shim", stdout);
    } else {
      fail("command through shim", `expected "hello_from_shim", got: ${stdout}`);
    }
  }

  // Test 7: session creation
  {
    console.log("\n=== Test 7: session creation ===");
    const result = await sandbox.sh`agentsh session create --workspace /home/user --json`;
    const stdout = result.stdout?.trim() ?? "";
    try {
      const json: Record<string, unknown> = JSON.parse(stdout);
      if ("id" in json && typeof json.id === "string" && json.id.length > 0) {
        pass("session creation", `session id: ${json.id}`);
      } else {
        fail("session creation", `JSON parsed but missing "id" field: ${stdout}`);
      }
    } catch {
      fail("session creation", `failed to parse JSON: ${stdout}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("Creating agentsh sandbox...");
  const sandbox = await createAgentshSandbox();

  try {
    await runTests(sandbox);
  } finally {
    console.log("\nCleaning up sandbox...");
    await sandbox.close();
  }

  console.log(`\nResults: ${passed} passed, ${failed} failed`);

  if (failed > 0) {
    Deno.exit(1);
  }
}

await main();
