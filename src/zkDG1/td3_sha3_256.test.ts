import { ZkTD3 } from "./td3_sha3_256.ts";

Deno.test.ignore("zkprog DG1 TD3", async () => {
  await ZkTD3.compile();
});
