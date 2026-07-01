package net.thiim.dilithium.provider;

import java.security.Provider;

public class DilithiumProvider extends Provider {

	public DilithiumProvider() {
		super("Dilithium Provider", "0.1", "For experimental use only");
		
			/*
		 * Key(pair) Generator engines
		 */
		put("KeyPairGenerator.Dilithium",
				"net.thiim.dilithium.provider.DilithiumKeyPairGenerator");
		put("Alg.Alias.KeyPairGenerator.Dilithium", "Dilithium");

		/*
		 * Key factories
		 */
		put("KeyFactory.Dilithium",
				"net.thiim.dilithium.provider.DilithiumKeyFactory");
		put("Alg.Alias.KeyFactory.Dilithium", "Dilithium");
		
		/*
		 * Signature engines
		 */
		put("Signature.Dilithium",
				"net.thiim.dilithium.provider.DilithiumSignature");
		put("Alg.Alias.Signature.Dilithium", "Dilithium");

	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

}
