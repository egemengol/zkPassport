import { VerificationKey, ZkProgram } from "o1js";
import { DynProofZkSign74_k1 } from "../zkSign/common.ts";

export const PartialSign = ZkProgram({
  name: "partial-sign",

  methods: {
    verifyCombine: {
      privateInputs: [
        VerificationKey,
        DynProofZkSign74_k1,
      ],

      // deno-lint-ignore require-await
      async method(
        vkDG1: VerificationKey,
        proofSign: DynProofZkSign74_k1,
      ) {
        proofSign.verify(vkDG1);
      },
    },
  },
});
