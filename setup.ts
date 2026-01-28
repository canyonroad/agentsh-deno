/**
 * setup.ts — Core bootstrap module for agentsh inside Deno Deploy Sandboxes.
 *
 * Exports `createAgentshSandbox()` which creates a fresh sandbox, installs
 * agentsh from GitHub releases, writes config/policy YAML files, starts the
 * agentsh server, and installs the shell shim. Returns a ready-to-use sandbox.
 */

import { Sandbox } from "@deno/sandbox";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AgentshSandboxOptions {
  /** GitHub repo for agentsh releases. Default: "erans/agentsh" */
  agentshRepo?: string;
  /** Architecture for .deb package. Default: "amd64" */
  debArch?: string;
  /** Workspace path inside sandbox. Default: "/home/user" */
  workspace?: string;
  /** Hosts to allow network access to. Needed for bootstrap (apt + GitHub). */
  allowNet?: string[];
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create a Deno Sandbox with agentsh installed, configured, and running.
 *
 * Bootstrap sequence:
 *   1. Install system dependencies (curl, jq, libseccomp2, sudo)
 *   2. Download and install agentsh from GitHub releases (.deb)
 *   3. Create required directories
 *   4. Write server config and security policy files
 *   5. Set permissions and passwordless sudo for agentsh
 *   6. Start agentsh server in background and wait for health check
 *   7. Install the shell shim (replaces /bin/bash)
 *
 * @param opts - Optional overrides for repo, architecture, and workspace path
 * @returns A ready Sandbox instance with agentsh running
 */
export async function createAgentshSandbox(
  opts?: AgentshSandboxOptions,
): Promise<Sandbox> {
  const repo = opts?.agentshRepo ?? "erans/agentsh";
  const arch = opts?.debArch ?? "amd64";
  const _workspace = opts?.workspace ?? "/home/user";

  // -------------------------------------------------------------------------
  // 1. Create sandbox with network access enabled (needed to download agentsh
  //    and system packages during bootstrap).
  // -------------------------------------------------------------------------
  const sandbox = await Sandbox.create({
    allowNet: opts?.allowNet,
  });
  console.log(`Sandbox created: ${sandbox.id}`);

  try {
    // -----------------------------------------------------------------------
    // 2. Install system dependencies
    // -----------------------------------------------------------------------
    console.log("Installing system dependencies...");
    await sandbox.sh`apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq libseccomp2 sudo && rm -rf /var/lib/apt/lists/*`;

    // -----------------------------------------------------------------------
    // 3. Download and install agentsh from GitHub releases
    //
    // NOTE: The install script uses shell variables ($LATEST_TAG, $version,
    // etc.). Because sandbox.sh is a tagged template literal, we must be
    // careful not to let JS interpolation swallow shell $-expressions. We
    // inject the *TypeScript* values (repo, arch) via template interpolation,
    // and pass shell-variable references as raw text that the shell will
    // expand at runtime.
    // -----------------------------------------------------------------------
    console.log("Installing agentsh...");
    const installScript = `set -eux
LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" | jq -r '.tag_name')
version="\${LATEST_TAG#v}"
deb="agentsh_\${version}_linux_${arch}.deb"
url="https://github.com/${repo}/releases/download/\${LATEST_TAG}/\${deb}"
echo "Downloading agentsh \${LATEST_TAG}: \${url}"
curl -fsSL -L "\${url}" -o /tmp/agentsh.deb
dpkg -i /tmp/agentsh.deb
rm -f /tmp/agentsh.deb
agentsh --version`;
    await sandbox.sh`${installScript}`;

    // -----------------------------------------------------------------------
    // 4. Create required directories
    // -----------------------------------------------------------------------
    console.log("Creating directories...");
    await sandbox.sh`mkdir -p /etc/agentsh/policies /var/lib/agentsh/quarantine /var/lib/agentsh/sessions /var/log/agentsh && chmod 755 /etc/agentsh /etc/agentsh/policies && chmod 755 /var/lib/agentsh /var/lib/agentsh/quarantine /var/lib/agentsh/sessions && chmod 755 /var/log/agentsh`;

    // -----------------------------------------------------------------------
    // 5. Write config and policy YAML files into the sandbox
    //
    // We resolve paths relative to this module so that the files are found
    // regardless of the caller's working directory.
    // -----------------------------------------------------------------------
    console.log("Writing configuration files...");
    const configYaml = await Deno.readTextFile(
      new URL("./config.yaml", import.meta.url),
    );
    const policyYaml = await Deno.readTextFile(
      new URL("./default.yaml", import.meta.url),
    );

    await writeFileToSandbox(sandbox, "/etc/agentsh/config.yaml", configYaml);
    await writeFileToSandbox(
      sandbox,
      "/etc/agentsh/policies/default.yaml",
      policyYaml,
    );

    // -----------------------------------------------------------------------
    // 6. Set ownership and permissions, add passwordless sudo for agentsh
    // -----------------------------------------------------------------------
    console.log("Setting permissions...");
    await sandbox.sh`chown -R user:user /var/lib/agentsh /var/log/agentsh /etc/agentsh`;
    await sandbox.sh`echo "user ALL=(ALL) NOPASSWD: /usr/bin/agentsh" >> /etc/sudoers`;

    await sandbox.env.set("AGENTSH_SERVER", "http://127.0.0.1:18080");

    // -----------------------------------------------------------------------
    // 7. Start agentsh server in background and wait for health check
    // -----------------------------------------------------------------------
    console.log("Starting agentsh server...");
    sandbox.spawn("agentsh", { args: ["server"] });

    console.log("Waiting for agentsh server to be ready...");
    await sandbox.sh`for i in $(seq 1 30); do if curl -sf http://127.0.0.1:18080/health > /dev/null 2>&1; then echo "agentsh server ready"; exit 0; fi; sleep 0.5; done; echo "agentsh server failed to start within 15s" >&2; exit 1`;

    // -----------------------------------------------------------------------
    // 8. Install the shell shim (replaces /bin/bash with agentsh-shell-shim)
    //
    // The shim transparently intercepts all bash invocations and routes them
    // through agentsh for policy enforcement.
    // -----------------------------------------------------------------------
    console.log("Installing shell shim...");
    await sandbox.sh`sudo agentsh shim install-shell --root / --shim /usr/bin/agentsh-shell-shim --bash --i-understand-this-modifies-the-host`;

    console.log("agentsh sandbox ready.");
    return sandbox;
  } catch (err) {
    // If bootstrap fails, clean up the sandbox so we don't leak resources.
    console.error("Bootstrap failed, cleaning up sandbox...");
    try {
      await sandbox.close();
    } catch {
      // Best-effort cleanup; ignore errors.
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Write a text file into the sandbox filesystem.
 */
async function writeFileToSandbox(
  sandbox: Sandbox,
  path: string,
  content: string,
): Promise<void> {
  await sandbox.fs.writeTextFile(path, content);
}
