package net.thiim.dilithium.test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

import org.junit.Test;

import net.thiim.dilithium.interfaces.DilithiumParameterSpec;
import net.thiim.dilithium.interfaces.DilithiumPrivateKey;
import net.thiim.dilithium.interfaces.DilithiumPrivateKeySpec;
import net.thiim.dilithium.interfaces.DilithiumPublicKey;
import net.thiim.dilithium.interfaces.DilithiumPublicKeySpec;
import net.thiim.dilithium.provider.DilithiumProvider;

public class BasicTests {
	private final static DilithiumParameterSpec[] specs = new DilithiumParameterSpec[] {
			DilithiumParameterSpec.LEVEL2,
			DilithiumParameterSpec.LEVEL3,
			DilithiumParameterSpec.LEVEL5
			
	};
	
	@Test
	public void keygen() throws Exception
	{
		for(DilithiumParameterSpec spec : specs) {
			DilithiumProvider pv = new DilithiumProvider();
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", pv);
			kpg.initialize(spec);
			KeyPair kp = kpg.generateKeyPair();		
			assertTrue(kp.getPublic() instanceof DilithiumPublicKey);
			assertTrue(kp.getPrivate() instanceof DilithiumPrivateKey);
		}
	}

	@Test
	public void signAndVerify() throws Exception
	{
		for(DilithiumParameterSpec spec : specs) {
			signAndVerifyWithSpec(spec);
		}
	}

	private void signAndVerifyWithSpec(DilithiumParameterSpec spec) throws Exception {
		DilithiumProvider pv = new DilithiumProvider();
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", pv);
		kpg.initialize(spec);
		KeyPair kp = kpg.generateKeyPair();
		
		KeyPair altKeyPair = kpg.generateKeyPair();
		
		for(int i = 0; i < 32; i++) {
			byte[] text = new byte[i];
			for(int j = 0; j < i; j++) {
				text[j] = (byte)j;
			}
			
			Signature signature = Signature.getInstance("Dilithium", pv);
			signature.initSign(kp.getPrivate());
			signature.update(text);
			byte[] sig = signature.sign();
			
			// Check we can verify with the correct public key
			signature.initVerify(kp.getPublic());
			signature.update(text);
			assertTrue(signature.verify(sig));
			
			// Check we can't with incorrect public key
			signature.initVerify(altKeyPair.getPublic());
			signature.update(text);
			assertFalse(signature.verify(sig));
			
			// Check we can detect any bit-level modification using the correct public key
			for(int j = 0; j < i; j++) {
				for(int k = 0; k < 8; k++) {
					byte[] alttext = Arrays.copyOf(text, text.length);
					alttext[j] ^= (1 << k);
					
					signature.initVerify(kp.getPublic());
					signature.update(alttext);
					assertFalse(signature.verify(sig));
				}
			}
			
		}
	}
	
	@Test
	public void testSerialization() throws Exception
	{
		for(DilithiumParameterSpec spec : specs) {
			testSerializationForSpec(spec);
		}
	}

	private void testSerializationForSpec(DilithiumParameterSpec spec) throws Exception {
		DilithiumProvider pv = new DilithiumProvider();
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium", pv);
		kpg.initialize(spec);
		KeyPair kp = kpg.generateKeyPair();
		
		Signature signature = Signature.getInstance("Dilithium", pv);
		signature.initSign(kp.getPrivate());
		signature.update("Joy!".getBytes());
		byte[] sig = signature.sign();
		
		// Check we can verify with reinstantiated public key
		KeyFactory kf = KeyFactory.getInstance("Dilithium", pv);
		PublicKey reconsPublicKey = kf.generatePublic(new DilithiumPublicKeySpec(spec, kp.getPublic().getEncoded()));
		signature.initVerify(reconsPublicKey);
		signature.update("Joy!".getBytes());
		assertTrue(signature.verify(sig));
		
		// Now sign with reinstantiated private key
		PrivateKey reconsPrivateKey = kf.generatePrivate(new DilithiumPrivateKeySpec(spec, kp.getPrivate().getEncoded()));
		signature.initSign(reconsPrivateKey);
		signature.update("Joy!".getBytes());
		sig = signature.sign();
		
		// Check we can verify wtih originap public key
		signature.initVerify(kp.getPublic());
		signature.update("Joy!".getBytes());
		assertTrue(signature.verify(sig));
	}
}
