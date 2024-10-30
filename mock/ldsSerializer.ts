import * as asn1js from "npm:asn1js";
import { DigestAlgo, getDigestAlgoOID } from "../src/common.ts";

export function prepareLDSSecurityObject(
  dgHashes: Map<number, Uint8Array>,
  hashAlgo: DigestAlgo,
): asn1js.Sequence {
  // Sort and convert hash entries to ASN.1 sequences
  const hashSequences = Array.from(dgHashes.entries())
    .sort(([a], [b]) => a - b) // Sort by datagroup number
    .map(([dgNumber, hash]) =>
      new asn1js.Sequence({
        value: [
          new asn1js.Integer({ value: dgNumber }),
          new asn1js.OctetString({ valueHex: hash }),
        ],
      })
    );

  // Use a shorter form for the algorithm identifier
  const algorithmIdentifier = new asn1js.Sequence({
    value: [
      new asn1js.ObjectIdentifier({ value: getDigestAlgoOID(hashAlgo) }),
      // new asn1js.Null(),
    ],
  });

  return new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: 0 }),
      // Hash algorithm identifier
      algorithmIdentifier,
      // Sequence of datagroup hashes
      new asn1js.Sequence({
        value: hashSequences,
      }),
    ],
  });
}

export function prepareSignedAttributes(ldsHash: Uint8Array): asn1js.Set {
  const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
  const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
  const OID_ICAO_LDS_SOD = "2.23.136.1.1.1";
  return new asn1js.Set({
    value: [
      // Content Type attribute
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: OID_CONTENT_TYPE }),
          new asn1js.Set({
            value: [
              new asn1js.ObjectIdentifier({ value: OID_ICAO_LDS_SOD }),
            ],
          }),
        ],
      }),
      // Message Digest attribute
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: OID_MESSAGE_DIGEST }),
          new asn1js.Set({
            value: [
              new asn1js.OctetString({ valueHex: ldsHash }),
            ],
          }),
        ],
      }),
    ],
  });
}
