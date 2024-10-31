import { Hash, Struct, ZkProgram } from "o1js";
import { DigestAlgo, getSignedAttrsBytes } from "../common.ts";
import { EcdsaSecp256k1, hashToScalar, Secp256k1 } from "./common.ts";

export const DIGEST_ALGO: DigestAlgo = "sha3-256";
const SIGNED_ATTRS_BYTES = getSignedAttrsBytes(DIGEST_ALGO);

class ZkSign_PubInput extends Struct({
  payload: SIGNED_ATTRS_BYTES,
  publicKey: Secp256k1,
  signature: EcdsaSecp256k1,
}) {}

export const ZkSign = ZkProgram({
  name: "sha3-256-secp256k1",
  publicInput: ZkSign_PubInput,

  methods: {
    verifySignature: {
      privateInputs: [],

      // deno-lint-ignore require-await
      async method(inp: ZkSign_PubInput) {
        const hash = Hash.SHA3_256.hash(inp.payload);
        const aff = hashToScalar(hash);
        const isValid = inp.signature.verifySignedHash(aff, inp.publicKey);
        isValid.assertTrue("signature validation failed");
      },
    },
  },
});
