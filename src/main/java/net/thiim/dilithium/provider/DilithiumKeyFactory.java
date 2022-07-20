package net.thiim.dilithium.provider;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import net.thiim.dilithium.impl.PackingUtils;
import net.thiim.dilithium.interfaces.DilithiumPrivateKeySpec;
import net.thiim.dilithium.interfaces.DilithiumPublicKeySpec;

public class DilithiumKeyFactory extends KeyFactorySpi {
	@Override
	protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
		if (!(keySpec instanceof DilithiumPublicKeySpec)) {
			throw new IllegalArgumentException("Invalid key spec");
		}
		DilithiumPublicKeySpec pubspec = (DilithiumPublicKeySpec) keySpec;
		return PackingUtils.unpackPublicKey(pubspec.getParameterSpec(), pubspec.getBytes());
	}

	@Override
	protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
		if (!(keySpec instanceof DilithiumPrivateKeySpec)) {
			throw new IllegalArgumentException("Invalid key spec");
		}
		DilithiumPrivateKeySpec prvspec = (DilithiumPrivateKeySpec) keySpec;
		return PackingUtils.unpackPrivateKey(prvspec.getParameterSpec(), prvspec.getBytes());
	}

	@Override
	protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
		throw new UnsupportedOperationException("Unsupported!");
	}

	@Override
	protected Key engineTranslateKey(Key key) throws InvalidKeyException {
		throw new UnsupportedOperationException("Unsupported!");
	}
}
