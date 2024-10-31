# Grokking eMRTDs

Let us logically understand how does a document is created, layer by layer.

```plantuml
@startuml
!theme blueprint

package TD1 [
  IDs, size 90
]
package TD2 [
  Visas, size 72
]
package TD3 [
  Passports, size 88
]

package "DG1 - one of three sizes" as DG1 {
  component "1: header" as DG1_header
  component "2: MRZ" as MRZ
}

TD1 .down.> MRZ
TD2 .down.> MRZ : oneof
TD3 .down.> MRZ

package DG2 [
  Biometric information
  Mandatory
  Dynamic size
]

package DG14 [
  Security Options
  Mandatory
  Dynamic size
]

package "LDS - dynamic number of DG hashes" as LDS {
  component "header" as LDS_header
  component "DG1 hash" as DG1_hash
  component "DG2 hash" as DG2_hash
  component "..." as DG_any
  component "DG14 hash" as DG14_hash
}

DG1 --> DG1_hash : hash
DG2 --> DG2_hash : hash
DG14 --> DG14_hash : hash

package "Signed Attributes" as SignedAttrs {
  component "header" as SA_header
  component "LDS hash" as LDS_hash
  component "Signing time\n(optional)" as signing_time
}

LDS --> LDS_hash : hash

component Signature

SignedAttrs --> Signature : hash+sign

@enduml
```

### DG1

DG1 header is 5 bytes, MRZ can be one of three sizes, depending on the document type.

Some MRZ examples below.

TD1: IDs, size 90

```
I<GBRP231458901<<<<<<<<<<<<<<<
6709224M2209151GBR<<<<<<<<<<<6
BAGGINS<<FRODO<<<<<<<<<<<<<<<<
```

TD2: Visas, size: 72

```
I<GBRBAGGINS<<FRODO<<<<<<<<<<<<<<<<<
P231458901GBR6709224M2209151<<<<<<<6
```

TD3: Passports - size: 88

```
P<GBRBAGGINS<<FRODO<<<<<<<<<<<<<<<<<<<<<<<<<
P231458901GBR6709224M2209151ZE184226B<<<<<18
```

### LDS - Logical Data Structure

This structure holds the list of data group hashes the document contains.

- The list is ordered
- Datagroups 1, 2 and 14 are mandatory
- A document can have up to 16 datagroups
- LDS header is 29 or 30 bytes, depending on the hash algorithm used. This is because the algorithm OIDs are of different length, in the header.
- Datagroup hashes are naturally the size of the hash algorithm output size.

Therefore, LDS size can be deduced by knowing the digest algorithm. Then, depending on the number of datagroups present, it can only be one of 14 different lengths.

The DG1 is always at the head, so at compile time we know the offset of DG1 hash, depending on the hashing algorithm.

### Signed Attributes

The header is fixed length, therefore LDS hash offset is fixed for all documents.

The third component is optional.

### Signature

The Signed Attributes payload is then hashed and signed by the issuer.

The hash algorithm used in signing can be different from the hashing algorithm used everywhere else.

The issuers use a big number of keys, so they create certificates to verify them against a much smaller set of public keys later.
