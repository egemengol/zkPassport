import { assert } from "jsr:@std/assert";
import { Bytes, UInt8 } from "o1js";
import { CheckHead, DynCheckHead, DynHead } from "./bytesDynamic.ts";

Deno.test("dyn bytes", async (t) => {
  const vk = (await CheckHead.compile()).verificationKey;
  await DynCheckHead.compile();

  const array = new Uint8Array(74);
  array[0] = 1;

  await t.step("prove", async () => {
    const proofHead = await CheckHead.checkHead({
      array: Bytes.from(array),
      head: UInt8.from(1),
    });
    assert(await CheckHead.verify(proofHead.proof));
    const dynProofHead = DynHead.fromProof(proofHead.proof);
    dynProofHead.verify(vk);

    const proofDynHead = await DynCheckHead.checkHead(vk, dynProofHead);
    assert(await DynCheckHead.verify(proofDynHead.proof));
  });
});
