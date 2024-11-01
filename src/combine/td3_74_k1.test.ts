import { Bytes } from "o1js";
import { sha3_256 } from "@noble/hashes/sha3";

import { DIGEST_ALGO, ZkTD3 } from "../zkDG1/td3_sha3_256.ts";
import { ZkSignSha3_256Secp256k1 } from "../zkSign/sha3_256_secp256k1.ts";
import { generateDG1 } from "../../mock/dg1.ts";
import { SignerSecp256k1 } from "../../mock/signerSecp256k1.ts";
import { mockLdsAndSignedAttrs } from "../../mock/ldsSerializer.ts";
import { DynProofZkSign74_k1 } from "../zkSign/common.ts";
import { Zk_TD3_74_k1 } from "./td3_74_k1.ts";
import { DynProofZkTD3_74 } from "../zkDG1/common.ts";
import { assert } from "jsr:@std/assert";

Deno.test("combine TD3 sha3_256 sha3_256+secp256k1", async (t) => {
  const signer = new SignerSecp256k1();
  const publicKey = signer.pubO1;
  const mock = generateDG1();
  const { lds, signedAttrs } = mockLdsAndSignedAttrs(
    mock.dg1,
    DIGEST_ALGO,
    new Set([1, 2, 6, 11, 12, 14]),
  );
  const signature = signer.sign(sha3_256(signedAttrs));

  const vkDG1 = (await ZkTD3.compile()).verificationKey;
  const vkSign = (await ZkSignSha3_256Secp256k1.compile()).verificationKey;
  await Zk_TD3_74_k1.compile();

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

  let dynProofSign: DynProofZkSign74_k1;
  await t.step("sign", async () => {
    const proofSign = await ZkSignSha3_256Secp256k1.verifySignature({
      payload: Bytes.from(signedAttrs),
      signature,
      publicKey,
    });
    assert(await ZkSignSha3_256Secp256k1.verify(proofSign.proof));
    dynProofSign = DynProofZkSign74_k1.fromProof(proofSign.proof);
    dynProofSign.verify(vkSign);
  });

  await t.step("combine", async () => {
    const proofCombo = await Zk_TD3_74_k1.verifyCombine(
      vkDG1,
      dynProofDG1,
      vkSign,
      dynProofSign,
    );
    console.log("345");

    await Zk_TD3_74_k1.verify(proofCombo.proof);
  });
});
