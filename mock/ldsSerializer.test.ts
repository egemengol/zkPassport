import { decodeBase64 } from "@std/encoding/base64";
import {
  prepareLDSSecurityObject,
  prepareSignedAttributes,
} from "./ldsSerializer.ts";
import { sha512 } from "@noble/hashes/sha2";
import { assertEquals } from "jsr:@std/assert";

import testInput from "./ldsSerializer.test.json" with { type: "json" };
import type { DigestAlgo } from "../src/common.ts";

Deno.test("LDS serializer", () => {
  const expected = {
    lds: decodeBase64(testInput.lds),
    signedAttributes: decodeBase64(testInput.signedAttributes),
  };
  const dgHashesIntermediate: { [key: string]: string } = testInput.dgHashes;
  const dgHashes = new Map<number, Uint8Array>(
    Object.entries(dgHashesIntermediate).map(([key, value]) => [
      parseInt(key),
      decodeBase64(value),
    ]),
  );
  const digestAlgo = testInput.digestAlgorithm as DigestAlgo;

  const lds = prepareLDSSecurityObject(dgHashes, digestAlgo);
  const ldsGot = new Uint8Array(lds.toBER());
  assertEquals(ldsGot, expected.lds);

  const ldsDigest = sha512(new Uint8Array(lds.toBER()));
  const signedAttrs = prepareSignedAttributes(ldsDigest);
  const signedAttrsGot = new Uint8Array(signedAttrs.toBER());

  assertEquals(signedAttrsGot, expected.signedAttributes);
});
