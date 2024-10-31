import { DIGEST_ALGO, ZkSign } from "./sha3_256_secp256k1.ts";
import { Bytes } from "o1js";
import { lengthSignedAttrs } from "../common.ts";
import { SignerSecp256k1 } from "../../mock/signerSecp256k1.ts";
import { digestFunc } from "../../mock/common.ts";

const SIGNED_ATTRS_LEN = lengthSignedAttrs(DIGEST_ALGO);
const HASHER = digestFunc(DIGEST_ALGO);

function randomPayload() {
  const randomData = new Uint8Array(SIGNED_ATTRS_LEN);
  crypto.getRandomValues(randomData);
  return randomData;
}

Deno.test("zksign sha3_256 secp256k1", async (t) => {
  await ZkSign.compile();
  const signer = new SignerSecp256k1();
  const publicKey = signer.pubO1;

  await t.step("proves", async () => {
    const payload = randomPayload();
    const signature = signer.sign(HASHER(payload));

    const proof = await ZkSign.verifySignature({
      payload: Bytes.from(payload),
      signature,
      publicKey,
    });

    await ZkSign.verify(proof.proof);
  });
});