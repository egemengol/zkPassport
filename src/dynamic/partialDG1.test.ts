import { Bytes } from "o1js";

import { DIGEST_ALGO, ZkTD3 } from "../zkDG1/td3_sha3_256.ts";
import { generateDG1 } from "../../mock/dg1.ts";
import { mockLdsAndSignedAttrs } from "../../mock/ldsSerializer.ts";
import { PartialDG1 } from "./partialDG1.ts";
import { DynProofZkTD3_74 } from "../zkDG1/common.ts";
import { assert } from "jsr:@std/assert";

Deno.test("partial dg1", async (t) => {
  const mock = generateDG1();
  const { lds, signedAttrs } = mockLdsAndSignedAttrs(
    mock.dg1,
    DIGEST_ALGO,
    new Set([1, 2, 6, 11, 12, 14]),
  );

  const vkDG1 = (await ZkTD3.compile()).verificationKey;
  await PartialDG1.compile();

  let dynProofDG1: DynProofZkTD3_74;
  await t.step("dg1", async () => {
    const proofDG1 = await ZkTD3.mrz2signedAttrs({
      dg1: Bytes.from(mock.dg1),
      signedAttrs: Bytes.from(signedAttrs),
    }, Bytes.from(lds));
    assert(await ZkTD3.verify(proofDG1.proof));
    dynProofDG1 = DynProofZkTD3_74.fromProof(proofDG1.proof);
    dynProofDG1.verify(vkDG1);
  });

  await t.step("partial dg1", async () => {
    const proofCombo = await PartialDG1.verifyCombine(
      vkDG1,
      dynProofDG1,
    );
    console.log("345");

    await PartialDG1.verify(proofCombo.proof);
  });
});
