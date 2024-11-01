import { VerificationKey, ZkProgram } from "o1js";
import { DynProofZkTD3_74 } from "../zkDG1/common.ts";

export const PartialDG1 = ZkProgram({
  name: "partial-dg1",

  methods: {
    verifyCombine: {
      privateInputs: [
        VerificationKey,
        DynProofZkTD3_74,
      ],

      // deno-lint-ignore require-await
      async method(
        vkDG1: VerificationKey,
        proofDG1: DynProofZkTD3_74,
      ) {
        proofDG1.verify(vkDG1);
      },
    },
  },
});
