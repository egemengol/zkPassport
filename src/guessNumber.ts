import { Field, ZkProgram } from "o1js";

export const ZkGuessNumber = ZkProgram({
  name: "guess-number",
  publicInput: Field,
  publicOutput: Field,

  methods: {
    guessNumber: {
      privateInputs: [Field],

      // deno-lint-ignore require-await
      async method(expect: Field, guess: Field) {
        expect.assertEquals(guess);
        return { publicOutput: guess };
      },
    },
  },
});
