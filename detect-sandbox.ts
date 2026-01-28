import { createAgentshSandbox } from "./setup.ts";

const sb = await createAgentshSandbox();
try {
  console.log(await sb.sh`agentsh detect`.text());
  console.log("--- JSON ---");
  console.log(await sb.sh`agentsh detect -o json`.text());
} finally {
  await sb.close();
}
