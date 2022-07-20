package net.thiim.dilithium.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import net.thiim.dilithium.impl.Dilithium;
import net.thiim.dilithium.impl.Utils;
import net.thiim.dilithium.interfaces.DilithiumParameterSpec;

public class DilithiumKeyPairGenerator extends KeyPairGeneratorSpi {
	private DilithiumParameterSpec params;
	private SecureRandom random;

	@Override
	public void initialize(int keysize, SecureRandom random) {
		throw new UnsupportedOperationException("Not implemented - you must specify a parameter spec");
	}

	@Override
	public KeyPair generateKeyPair() {
		if(random == null || params == null) {
			throw new IllegalStateException("The generator is not configured");
		}
		byte[] seed = new byte[32];
		try {
			random.nextBytes(seed);
			return Dilithium.generateKeyPair(params, seed);
		}
		finally {
			Utils.clear(seed);
		}
	}

	@Override
	public void initialize(AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidAlgorithmParameterException {
		if (!(params instanceof DilithiumParameterSpec)) {
			throw new InvalidAlgorithmParameterException("Inappropriate parameter type");
		}
		this.params = (DilithiumParameterSpec) params;
		this.random = random;
	}
}
