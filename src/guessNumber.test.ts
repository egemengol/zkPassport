import { assertEquals } from "jsr:@std/assert";
import { Field } from "o1js";
import { ZkGuessNumber } from "./guessNumber.ts";

Deno.test.ignore("guess number", async () => {
  await ZkGuessNumber.compile();
  const proof = await ZkGuessNumber.guessNumber(Field(1), Field(1));
  assertEquals(await ZkGuessNumber.verify(proof.proof), true);
});
