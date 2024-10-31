import { Bytes, Hash, ZkProgram } from "o1js";
import { dg1OffsetInLDS, ZkTD3_PubInput_74 } from "./common.ts";
import {
  assertSubarray,
  DigestAlgo,
  LDS_DIGEST_OFFSET_IN_SIGNED_ATTRS,
  lengthDigest,
  lengthSignedAttrs,
} from "../common.ts";
import { assertEquals } from "jsr:@std/assert";

// BEWARE!! This is temporary, I dont know how to pass dynamic sized Bytes array
// This includes 6 data groups in it. 138 bytes for 3 datagroups.
class LDS extends Bytes(256) {}

export const DIGEST_ALGO: DigestAlgo = "sha3-256";
const DIGEST_SIZE = lengthDigest(DIGEST_ALGO);
const DG1_OFFSET = dg1OffsetInLDS(DIGEST_ALGO);

assertEquals(lengthSignedAttrs(DIGEST_ALGO), 74);

export const ZkTD3 = ZkProgram({
  name: "td3-sha3_256",
  publicInput: ZkTD3_PubInput_74,

  methods: {
    mrz2signedAttrs: {
      privateInputs: [LDS],

      // deno-lint-ignore require-await
      async method(inp: ZkTD3_PubInput_74, lds: LDS) {
        // const [year] = extractBirthdayTD3(inp.dg1);
        // year.assertEquals(inp.birthYear);

        const dg1Digest = Hash.SHA3_256.hash(inp.dg1);
        assertSubarray(lds.bytes, dg1Digest.bytes, DIGEST_SIZE, DG1_OFFSET);

        const ldsDigest = Hash.SHA3_256.hash(lds);
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
