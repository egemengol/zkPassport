import { Bytes, Field, Hash, Struct, ZkProgram } from "o1js";
import { DG1_TD3, dg1OffsetInLDS, extractBirthdayTD3 } from "./common.ts";
import {
  assertSubarray,
  DigestAlgo,
  getSignedAttrsBytes,
  LDS_DIGEST_OFFSET_IN_SIGNED_ATTRS,
  lengthDigest,
} from "../common.ts";

// BEWARE!! This is temporary, I dont know how to pass dynamic sized Bytes array
class LDS extends Bytes(256) {}

const DIGEST_ALGO: DigestAlgo = "sha3-256";
const DIGEST_SIZE = lengthDigest(DIGEST_ALGO);
const DG1_OFFSET = dg1OffsetInLDS(DIGEST_ALGO);
const SIGNED_ATTRS_BYTES = getSignedAttrsBytes(DIGEST_ALGO);

class ZkTD3_PubInput extends Struct({
  dg1: DG1_TD3,
  lds: LDS,
  signedAttrs: SIGNED_ATTRS_BYTES,
  birthYear: Field,
}) {}

export const ZkTD3 = ZkProgram({
  name: "td3-sha3_256",
  publicInput: ZkTD3_PubInput,

  methods: {
    mrz2lds: {
      privateInputs: [],

      // deno-lint-ignore require-await
      async method(inp: ZkTD3_PubInput) {
        const [year] = extractBirthdayTD3(inp.dg1);
        year.assertEquals(inp.birthYear);

        const dg1Digest = Hash.SHA3_256.hash(inp.dg1);
        assertSubarray(inp.lds.bytes, dg1Digest.bytes, DIGEST_SIZE, DG1_OFFSET);

        const ldsDigest = Hash.SHA3_256.hash(inp.lds);
        assertSubarray(
          inp.signedAttrs.bytes,
          ldsDigest.bytes,
          DIGEST_SIZE,
          LDS_DIGEST_OFFSET_IN_SIGNED_ATTRS,
        );
      },
    },
  },
});
