# CRYSTALS - Dilithium

This is a Java implementation of Dilithium (version 3.1 -- see below), based on the C reference implementation and documentation (see https://github.com/pq-crystals/dilithium). Further, I've wrapped the raw primitives into a JCE provider, making it easy to use via a standardized interface. 

So what is Dilithium? The cryptographic algorithms RSA and ECC have long been known to be vulnerable to attacks using quantum computers via Shor's algorithm. While quantum computers of the prerequisite size do not yet exist in practice, there's an ongoing search for algorithms that don't have this vulnerability. In fact, [NIST](https://www.nist.gov/) has been running a competition for over 6 years in order to identify quantum-safe alternatives. On July 5th NIST [announced](https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms) the three picks for Post-quantum digital signature schemes. Dilithium was among the three and was in fact recommended as the primary algorithm. Big congratulations to the authors! I wanted to study this new algorithm, and what better way than to try and implement it. This is what you are looking at :-)

Dilithium is part of the CRYSTALS suite of algorithms and is based on algebraic lattices. Think linear algebra but where the matrix/vector entries are polynomials in the ring $R_q = \mathbb{Z}_q[X]/(X^n+1)$. For much more information (including the specification and C reference implementation I used), see [their page](https://pq-crystals.org/index.shtml). Note, however, that the version described here is slightly different from the later 3.1 reference implementation, referred to in the above.

Like the reference implementation, this implementation supports all three documented security levels (levels 2, 3 and 5), all using the deterministic signature scheme. It passes all the KAT tests from the package. It supports serialization and deserialization using the documented formats.

I have a dependency on Bouncy castle, which provides the SHAKE128/256 algorithms used internally in Dilithium.

*IMPORTANT! This is a "for fun" implementation written in a couple of days. It's not intended to be production-grade code. No warranty or support of any kind is provided. However, it can be useful for diving into and experimenting with post-quantum algorithms. Use it at your own risk. If you don't like those terms, you must refrain from using this software.*

## Version
Originally I implemented the version that the Dilithium team submitted to the competition. The team has since made minor changes to some parameters (reducing the size of some, switching to SHAKE256 for some invocations etc.) which are reflected in the current reference implementation. This version is often referred to as 3.1. I've updated my implementation to reflect this.

At the same time, Dilithium is currently in the process of standardization into what will eventually become FIPS 204 or ML-DSA. This version is different from both the original submission as well as Dilithium 3.1 implemented here (and so also the Dilithium team reference implementation). At the time of writing I don't think it's worth implementing those changes, since many comments have already been submitted so it likely won't be final. Also I'm not aware of other implementations following it. Once the standard seems more stable and the comment period has ended I will definitely add a mode to support this new version (even if still in draft).

## Loading the security provider

```bash
DilithiumProvider provider = new DilithiumProvider();
Security.addProvider(provider);
```

If you wish, instead of adding the provider using addProvider(), you can omit this line and explicitly provide the provider-object when calling the .getInstance() methods (see below).

## Key pair generation
To generate a key pair you use:

```bash
SecureRandom sr = new SecureRandom();
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium");
kpg.initialize(DilithiumParameterSpec.LEVEL2, sr);			
KeyPair kp = kpg.generateKeyPair();
```

Note that you must provide an algorithm parameter spec representing the desired security level - the above example uses level 2, but you can select 3 and 5 as well. The three parameter spec objects are declared as static fields on the DilithiumParameterSpec class. Alternatively, a static method, getSpecForSecurityLevel(), is provided on DilithiumParameterSpec, allowing you to easily retrieve the spec for a given level at runtime. 

## Signing
Having generated a key pair, signing works just the same as for other JCE providers. The example below signs a byte representation of "Joy!".

```bash
Signature sig = Signature.getInstance("Dilithium");
sig.initSign(kp.getPrivate());
sig.update("Joy!".getBytes());
byte[] signature = sig.sign();
```
## Signature verification
Just as for signing, verification works as for other JCE providers

```bash
Signature sig = Signature.getInstance("Dilithium");
sig.initVerify(kp.getPublic());
sig.update("Joy!".getBytes());
boolean b = sig.verify(signature);
```
The boolean variable b now contains the outcome of the verification. Note that exceptions may be thrown in case of malformed signatures (as opposed to signatures that are merely incorrect). 

## Key serialization/deserialization
You can use the .getEncoded() method on the public and private key objects to obtain a byte representation of the key. The formats are compatible with the reference implementation.
In order to instantiate the keys from the byte representation, a key factory is provided. You can use this with the provided DilithiumPublicKeySpec and DilithiumPrivateKeySpec classes.
They are constructed using two parameters, namely the parameter spec (same as used for generating) and the byte representation. Note that the parameter spec is not encoded into the byte representation, and I decided to make the parameter choice explit rather than trying to infer it from length. In the future, I anticipate that ASN.1-based formats with OID's etc. will be standardized, and they will then explcitly encode the parameters. Of course, the serialization format could change as well as the standardization process moves along.

```bash
byte[] pubkeyBytes = kp.getPublic().getEncoded(); // This is our bytes to be instantiated
KeyFactory kf = KeyFactory.getInstance("Dilithium");
PublicKey reconstructedPublicKey = kf.generatePublic(new DilithiumPublicKeySpec(spec, pubkeyBytes));
```

The private key may be reconstructed in the same fashion, using the DilithiumPrivateKeySpec class.

## Low-level use
As an alternative to the low-level interface you can also use the static methods in the Dilithium class directly to generate, sign and verify. See e.g. how the JCE classes do it.

## Running the known-answer tests
The official Dilithium package contains a known-answer test generator that generates a request and response file. I've provided a Java utility in KAT.java that can read the 
request file generated by the reference implementation, run through the tests and generate a corresponding response file. You can then compare this response file to the one
generated by the official known-answer test generator and verify that they are byte-identical. The KAT.java program is run with parameters: 

```bash
 <input-request-file> <output-response-file> <level>
```
Note that the desired security level (2, 3 or 5) must be provided as the 3rd argument. This must match what is configured in the config.h file in the C implementation when generating the response file used for comparison.

## DISCLAIMER
This library is available under the Apache 2.0 license (see LICENSE). Note that the code has not been examined by a third party for potential vulnerabilities and as mentioned was not made to be used for production use. No warranty of any kind is provided. If you don't like those terms, you must refrain from using this software.

## References
For more information on the CRYSTALS project, see their [website](https://pq-crystals.org/index.shtml).

## Contact
Mail: martin@thiim.net
