import { DIGEST_ALGO, ZkTD3 } from "./td3_sha3_256.ts";
import { generateDG1 } from "../../mock/dg1.ts";
import { mockLdsAndSignedAttrs } from "../../mock/ldsSerializer.ts";
import { Bytes, Field } from "o1js";

Deno.test("zkprog DG1 TD3", async (t) => {
  await ZkTD3.compile();

  await t.step("proves", async () => {
    const mock = generateDG1();
    const { lds, signedAttrs } = mockLdsAndSignedAttrs(
      mock.dg1,
      DIGEST_ALGO,
      new Set([1, 2, 6, 11, 12, 14]),
    );
    const birthYear = parseInt(mock.dateOfBirth.slice(0, 2));
    const proof = await ZkTD3.mrz2signedAttrs({
      dg1: Bytes.from(mock.dg1),
      signedAttrs: Bytes.from(signedAttrs),
      birthYear: Field(birthYear),
    }, Bytes.from(lds));

    await ZkTD3.verify(proof.proof);
  });
});
