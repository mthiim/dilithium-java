package net.thiim.dilithium.provider;

import java.security.AccessController;
import java.security.Provider;

public class DilithiumProvider extends Provider {

	public DilithiumProvider() {
		super("Dilithium Provider", "0.1", "For experimental use only");
		
		 AccessController.doPrivileged(new java.security.PrivilegedAction<Object>() {
	            @Override
	            public Object run() {
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
                     * Key factories
	                 */
	                put("Signature.Dilithium",
	                        "net.thiim.dilithium.provider.DilithiumSignature");
	                put("Alg.Alias.Signature.Dilithium", "Dilithium");

	                return null;
	            }
	        });

	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

}
