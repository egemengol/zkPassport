## Current Situation

We can do `DG1 -> LDS -> SignedAttrs` and **Signature** verification with the algorithms `o1js` provides. `o1js` upstream already has `secp256r1` which is excellent, thanks to zkSecurity team there.

We can read real documents (ID and Passport) with React Native application on both iOS and Android.

We can create mock passports that use o1js supported algorithms so that we can run our circuits.

**Problem 1**: o1js hash implementations currently cover the following algos from SHA family, which needs to be expanded:

- sha256
- sha3_256
- sha3_384
- sha3_512

**Problem 2**: We need to hash LDS, which should be considered dynamic length. This will either be solved with some dynamic-length hashing (like how mina-credentials already implemented for sha256) or with extreme hacking to unroll the 14 different possible LDS lengths into hardcoded circuits.

**Problem 3**: We need to connect these different responsibility circuits together.

The solution is `DynamicProof`s, and there is the happy news about dynamic proofs only caring about the public inputs and outputs, therefore reducing the variation space.  
For example, we can use the same connector (with different verification key) for documents with hashing algorithms sha256 and sha3_256.

Still, the connector layer will include many zkPrograms to cover the variation space, we would really appreciate some input on designing this part.

**Problem 4**: We want to create these proofs on mobile application within webview, which is able to create simple proofs but not huge ones. We would love to hear success stories on that front if there is any.
