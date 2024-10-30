import { sha256, sha512 } from "@noble/hashes/sha2";
import * as base64 from "jsr:@std/encoding/base64";
import * as hex from "jsr:@std/encoding/hex";
import * as jsrsasign from "jsrsasign";
import { p256, secp256r1 } from "@noble/curves/p256"; // secp256r1
import { secp256k1 } from "@noble/curves/secp256k1";
import { p521 } from "@noble/curves/p521"; // secp256r1
import { createEcdsa, createForeignCurve, Crypto } from "o1js";

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

  // const r = BigInt("0x" + sig.r.toString(16));
  // const s = BigInt("0x" + sig.s.toString(16));

  return new Ecdsa({
    r: sig.r,
    s: sig.s,
  });
}

function parsePublicKeySecp256k1(publicKey: Uint8Array): Secp256k1 {
  const uncompressedPub = secp256k1.ProjectivePoint.fromHex(publicKey)
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

function main() {
  const mock: MockParse = JSON.parse(
    Deno.readTextFileSync("./mock.json"),
  );

  if (
    mock.hash_algo !== "sha3_256" || mock.sign_algo[0] !== "sha3_256" ||
    mock.sign_algo[1] !== "secp256k1"
  ) {
    throw Error("unexpected algos");
  }

  const dg1 = base64.decodeBase64(mock.dg1);
  const lds = base64.decodeBase64(mock.lds);
  const signedAttrs = base64.decodeBase64(mock.signed_attrs);
  const signature = base64.decodeBase64(mock.signature);
  const publicKeyUncompressedDer = base64.decodeBase64(
    mock.public_key_uncompressed_der,
  );
}
