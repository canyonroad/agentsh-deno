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
    const stdout = (await sandbox.sh`agentsh --version`.text()).trim();
    if (stdout.includes("agentsh")) {
      pass("agentsh installation", stdout);
    } else {
      fail("agentsh installation", `expected stdout to include "agentsh", got: ${stdout}`);
    }
  }

  // Test 2: server health
  {
    console.log("\n=== Test 2: server health ===");
    const stdout = (await sandbox.sh`curl -s http://127.0.0.1:18080/health`.text()).trim();
    if (stdout === "ok") {
      pass("server health", stdout);
    } else {
      fail("server health", `expected "ok", got: ${stdout}`);
    }
  }

  // Test 3: policy file
  {
    console.log("\n=== Test 3: policy file ===");
    const stdout = await sandbox.sh`head -5 /etc/agentsh/policies/default.yaml`.text();
    if (stdout.includes("version")) {
      pass("policy file", "contains 'version'");
    } else {
      fail("policy file", `expected to include "version", got: ${stdout}`);
    }
  }

  // Test 4: config file
  {
    console.log("\n=== Test 4: config file ===");
    const stdout = await sandbox.sh`head -5 /etc/agentsh/config.yaml`.text();
    if (stdout.includes("server")) {
      pass("config file", "contains 'server'");
    } else {
      fail("config file", `expected to include "server", got: ${stdout}`);
    }
  }

  // Test 5: shell shim
  {
    console.log("\n=== Test 5: shell shim ===");
    const stdout = await sandbox.sh`test -x /usr/bin/agentsh-shell-shim && echo "SHIM_OK" || echo "SHIM_MISSING"`.text();
    if (stdout.includes("SHIM_OK")) {
      pass("shell shim", "/usr/bin/agentsh-shell-shim exists");
    } else {
      fail("shell shim", "agentsh-shell-shim not found");
    }
  }

  // Test 6: command through shim
  {
    console.log("\n=== Test 6: command through shim ===");
    const stdout = (await sandbox.sh`/bin/bash -c "echo hello_from_shim"`.text()).trim();
    if (stdout.includes("hello_from_shim")) {
      pass("command through shim", stdout);
    } else {
      fail("command through shim", `expected "hello_from_shim", got: ${stdout}`);
    }
  }

  // Test 7: session creation
  {
    console.log("\n=== Test 7: session creation ===");
    const stdout = (await sandbox.sh`agentsh session create --workspace /app --json`.text()).trim();
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
