import { sha256, sha512 } from "@noble/hashes/sha2";
import * as base64 from "jsr:@std/encoding/base64";
import * as hex from "jsr:@std/encoding/hex";
import * as jsrsasign from "jsrsasign";
import { p256, secp256r1 } from "@noble/curves/p256"; // secp256r1
import { secp256k1 } from "@noble/curves/secp256k1";
import { p521 } from "@noble/curves/p521"; // secp256r1

// import { type Buffer } from "node:buffer";

interface PassportData {
  mrzKey: string;
  scannedDataGroupList: DataGroupTuple[];
  openPassportData: OpenPassportData;
}

type DataGroupTuple = [string, string]; // ("DG1", base64)

interface OpenPassportData {
  dateOfBirth: string;
  documentSigningCertificate: string; // DocumentSigningCertificate as JSON
  documentNumber: string;
  dataGroupsPresent: string;
  passportMRZ: string;
  signatureBase64: string;
  encapsulatedContentDigestAlgorithm: string;
  signatureAlgorithm: string;
  eContentBase64: string;
  signedAttributes: string;
}

interface DocumentSigningCertificate {
  Issuer: string;
  SerialNumber: string;
  SignatureAlgorithm: string;
  ValidFrom: string;
  PublicKeyAlgorithm: string;
  PEM: string;
  ValidTo: string;
  Subject: string;
  CertificateFingerprint: string;
}

const findDGBase64 = (dgTuples: DataGroupTuple[], id: string) => {
  const dgTuple = dgTuples.find((tup) => tup[0] === id)!;
  return dgTuple[1];
};

function isDG1HashInSOD(dgTuples: DataGroupTuple[]): boolean {
  const dg1Base64 = findDGBase64(dgTuples, "DG1");
  const dg1Hash = sha512(base64.decodeBase64(dg1Base64));
  const dg1HashBase64 = base64.encodeBase64(dg1Hash).replace(/=+$/, "");

  const sodBase64 = findDGBase64(dgTuples, "SOD");

  return sodBase64.includes(dg1HashBase64.slice(0, -1)); // WHY the last character is out?
}

function isEContentSigned(
  eContent: Uint8Array,
  certObj: DocumentSigningCertificate,
  signature: Uint8Array,
): boolean {
  const certificate: jsrsasign.X509 = new jsrsasign.X509();
  certificate.readCertPEM(certObj.PEM);
  const publicKey = hex.decodeHex(certificate.getPublicKey().pubKeyHex);
  const payload = sha512(eContent);
  return p521.verify(signature, payload, publicKey);
}

function main() {
  const passportExport: PassportData = JSON.parse(
    Deno.readTextFileSync("./halit.json"),
  );

  console.log(
    "Is DG1 in SOD:",
    isDG1HashInSOD(passportExport.scannedDataGroupList),
  );

  const eContent = base64.decodeBase64(
    passportExport.openPassportData.eContentBase64,
  );
  const certObj: DocumentSigningCertificate = JSON.parse(
    passportExport.openPassportData.documentSigningCertificate,
  );
  const signature = base64.decodeBase64(
    passportExport.openPassportData.signatureBase64,
  );
  console.log(
    "Is SOD signed:",
    isEContentSigned(eContent, certObj, signature),
  );

  const signedAttributes = base64.decodeBase64(
    passportExport.openPassportData.signedAttributes,
  );
  console.log(
    "Is signedAttributes signed:",
    isEContentSigned(signedAttributes, certObj, signature),
  );
}

await main();
