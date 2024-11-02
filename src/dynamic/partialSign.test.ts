import { Bytes, FeatureFlags } from "o1js";
import { sha3_256 } from "@noble/hashes/sha3";

import { ZkSignSha3_256Secp256k1 } from "../zkSign/sha3_256_secp256k1.ts";
import { SignerSecp256k1 } from "../../mock/signerSecp256k1.ts";
import { DynProofZkSign74_k1 } from "../zkSign/common.ts";
import { PartialSign } from "./partialSign.ts";
import { assert } from "jsr:@std/assert";

Deno.test("partial sign", async (t) => {
  const signer = new SignerSecp256k1();
  const publicKey = signer.pubO1;
  const payload = new Uint8Array(74);
  payload[0] = 1;
  const signature = signer.sign(sha3_256(payload));

  console.log(await FeatureFlags.fromZkProgram(ZkSignSha3_256Secp256k1));

  const vkSign = (await ZkSignSha3_256Secp256k1.compile()).verificationKey;
  await PartialSign.compile();

  let dynProofSign: DynProofZkSign74_k1;
  await t.step("sign", async () => {
    const proofSign = await ZkSignSha3_256Secp256k1.verifySignature({
      payload: Bytes.from(payload),
      signature,
      publicKey,
    });
    assert(await ZkSignSha3_256Secp256k1.verify(proofSign.proof));
    dynProofSign = DynProofZkSign74_k1.fromProof(proofSign.proof);
    dynProofSign.verify(vkSign);
  });

  await t.step("partial sign", async () => {
    const proofCombo = await PartialSign.verifyCombine(
      vkSign,
      dynProofSign,
    );
    console.log("345");

    await PartialSign.verify(proofCombo.proof);
  });
});
