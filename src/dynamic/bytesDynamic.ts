import {
  Bytes,
  DynamicProof,
  Struct,
  UInt8,
  VerificationKey,
  Void,
  ZkProgram,
} from "o1js";

export class Bytes74 extends Bytes(74) {}

export class CheckHeadPubInput extends Struct({
  array: Bytes74,
  head: UInt8,
}) {}

export const CheckHead = ZkProgram({
  name: "check-head",
  publicInput: CheckHeadPubInput,

  methods: {
    checkHead: {
      privateInputs: [],

      // deno-lint-ignore require-await
      async method(
        pub: CheckHeadPubInput,
      ) {
        pub.array.bytes[0].assertEquals(pub.head);
      },
    },
  },
});

export class DynHead extends DynamicProof<CheckHeadPubInput, Void> {
  static override publicInputType = CheckHeadPubInput;
  static override publicOutputType = Void;
  static override maxProofsVerified = 0 as const;
}

export const DynCheckHead = ZkProgram({
  name: "dyn-check-head",

  methods: {
    checkHead: {
      privateInputs: [VerificationKey, DynHead],

      // deno-lint-ignore require-await
      async method(
        vk: VerificationKey,
        proof: DynHead,
      ) {
        proof.verify(vk);
      },
    },
  },
});
