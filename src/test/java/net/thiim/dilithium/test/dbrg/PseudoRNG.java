package net.thiim.dilithium.test.dbrg;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.drbg.CTRSP800DRBG;

public class PseudoRNG {
	private ModifiedSP80090DRBG ctr;

	public PseudoRNG(final byte[] entropy, byte[] personalization, int strength)
	{
		AESEngine eng = new AESEngine();
		BlockCipher bc;
		EntropySource es = new EntropySource() {
			@Override
			public int entropySize() {
				return 8*entropy.length;
			}

			@Override
			public byte[] getEntropy() {
				return entropy;
			}

			@Override
			public boolean isPredictionResistant() {
				return false;
			}
		};
		this.ctr = new ModifiedSP80090DRBG(eng, 256, strength, es, personalization, null);
		
	}
	
	public byte[] generate(int amount)
	{
		byte[] b = new byte[amount];
		this.ctr.generate(b, null, false);
		return b;
	}
}
