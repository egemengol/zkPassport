import { sha256, sha512 } from "@noble/hashes/sha2";
import * as base64 from "jsr:@std/encoding/base64";
import * as hex from "jsr:@std/encoding/hex";
import * as jsrsasign from "jsrsasign";
import { p256, secp256r1 } from "@noble/curves/p256"; // secp256r1
import { secp256k1 } from "@noble/curves/secp256k1";
import { p521 } from "@noble/curves/p521"; // secp256r1
import {
  Bytes,
  createEcdsa,
  createForeignCurve,
  Crypto,
  Hash,
  UInt8,
} from "o1js";

interface MockParse {
  "hash_algo": string;
  "sign_algo": [string, string];
  "dg1": string;
  "lds": string;
  "signed_attrs": string;
  "signature": string;
  "public_key_uncompressed_der": string;
}

export class Secp256k1 extends createForeignCurve(
  Crypto.CurveParams.Secp256k1,
) {}
export class Ecdsa extends createEcdsa(Secp256k1) {}

function parseSignatureSecp256k1(signature: Uint8Array): Ecdsa {
  const sig = secp256k1.Signature.fromDER(signature);

  return new Ecdsa({
    r: sig.r,
    s: sig.s,
  });
}

function parsePublicKeySecp256k1(publicKey: Uint8Array): Secp256k1 {
  const uncompressedPub = secp256k1.ProjectivePoint.fromHex(
    hex.encodeHex(publicKey),
  )
    .toRawBytes(false);
  const xArr = uncompressedPub.slice(1, 33);
  const yArr = uncompressedPub.slice(33);
  const x = BigInt("0x" + hex.encodeHex(xArr));
  const y = BigInt("0x" + hex.encodeHex(yArr));
  return new Secp256k1({
    x,
    y,
  });
}

function bytesToLimbBE(bytes_: UInt8[]) {
  const bytes = bytes_.map((x) => x.value);
  const n = bytes.length;
  let limb = bytes[0];
  for (let i = 1; i < n; i++) {
    limb = limb.mul(1n << 8n).add(bytes[i]);
  }
  return limb.seal();
}

function hashToScalar(hash: Bytes) {
  const x2 = bytesToLimbBE(hash.bytes.slice(0, 10));
  const x1 = bytesToLimbBE(hash.bytes.slice(10, 21));
  const x0 = bytesToLimbBE(hash.bytes.slice(21, 32));

  return new Secp256k1.Scalar.AlmostReduced([x0, x1, x2]);
}

Deno.test("direct mock", () => {
  const mock: MockParse = JSON.parse(
    Deno.readTextFileSync("./mock.json"),
  );

  if (
    mock.hash_algo !== "sha3_256" || mock.sign_algo[0] !== "sha3_256" ||
    mock.sign_algo[1] !== "secp256k1"
  ) {
    throw Error("unexpected algos");
  }

  const dg1 = Bytes.from(base64.decodeBase64(mock.dg1));
  const lds = Bytes.from(base64.decodeBase64(mock.lds));
  const signedAttrs = Bytes.from(base64.decodeBase64(mock.signed_attrs));
  const signature = parseSignatureSecp256k1(
    base64.decodeBase64(mock.signature),
  );
  const publicKey = parsePublicKeySecp256k1(base64.decodeBase64(
    mock.public_key_uncompressed_der,
  ));

  /*
      The offset of 29 bytes comes from:
      1. SEQUENCE tag + length (2 bytes)
      2. Version INTEGER tag + length + value (3 bytes)
      3. hashAlgorithm SEQUENCE tag + length (2 bytes)
      4. algorithm OID tag + length (2 bytes)
      5. OID value (19 bytes)
      6. NULL tag + length (2 bytes)
      7. dataGroupHashes SEQUENCE tag + length (2 bytes)
      8. First DataGroupHash SEQUENCE starts here

      Total: 2 + 3 + 2 + 2 + 19 + 2 + 2 = 29 bytes

      sha512 and sha3_256 OID lengths are both 19
  */
  let offset = 29;
  const dg1Digest = Hash.SHA3_256.hash(dg1);
  for (let i = 0; i < 32; i += 1) {
    lds.bytes.at(offset + i)!.assertEquals(dg1Digest.bytes.at(i)!);
  }

  /*
      The offset of 42 bytes comes from:

      Part 1: Outer SET tag + length
      [30 15] = 2 bytes

      Part 2: First attribute (content_type)
      - SEQUENCE tag + length [30 15] = 2 bytes
      - type OID tag + length [06 09] = 2 bytes
      - type OID value [2a864886f70d010903] = 9 bytes
      - values SET tag + length [31 08] = 2 bytes
      - inner OID tag + length [06 06] = 2 bytes
      - inner OID value [678108010101] = 6 bytes
      Subtotal for first attribute = 23 bytes

      Part 3: Second attribute (message_digest) header
      - SEQUENCE tag + length [30 2f] = 2 bytes
      - type OID tag + length [06 09] = 2 bytes
      - type OID value [2a864886f70d010904] = 9 bytes
      - values SET tag + length [31 22] = 2 bytes
      - OCTET STRING tag + length [04 20] = 2 bytes
      Subtotal for second attribute header = 17 bytes

      Total: 2 + 23 + 17 = 42 bytes
  */
  offset = 42;
  const ldsDigest = Hash.SHA3_256.hash(lds);
  for (let i = 0; i < 32; i += 1) {
    signedAttrs.bytes.at(offset + i)!.assertEquals(ldsDigest.bytes.at(i)!);
  }

  // verify sign
  const aff = hashToScalar(Hash.SHA3_256.hash(signedAttrs));
  const isValidSign = signature.verifySignedHash(aff, publicKey);
  isValidSign.assertTrue("sign");
});
