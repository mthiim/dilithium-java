package net.thiim.dilithium.test;

import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import net.thiim.dilithium.interfaces.DilithiumParameterSpec;
import net.thiim.dilithium.provider.DilithiumProvider;

/**
 * Quick and dirty test that exercises the functionality, including testing that serialization/deserialization works as expected.
 * It also provides some simple performance measurements.
 *
 */
public class PerfTest {
	@Test	
	public void test() throws Exception
	{
		DilithiumProvider provider = new DilithiumProvider();
		Security.addProvider(provider);
		
		SecureRandom sr = new SecureRandom();
		
		DilithiumParameterSpec[] specs = new DilithiumParameterSpec[] {
				DilithiumParameterSpec.LEVEL2,
				DilithiumParameterSpec.LEVEL3,
				DilithiumParameterSpec.LEVEL5
				
		};
		
		Map<DilithiumParameterSpec, Timings> timings = new HashMap<DilithiumParameterSpec, Timings>();
		for(DilithiumParameterSpec s : specs) {
			timings.put(s,  new Timings());
		}
		
		final int CNT = 1000;
		final int WARMUP = 500;
		boolean warmingup = true;
		System.out.println("Test running...please hold on...");
		for(int i = 0; i < CNT; i++) {
			if(i % 100 == 0) {
				System.out.println("" + i + " out of " + CNT + " iterations.");
			}
			if(i >= WARMUP) {
				warmingup = false;
			}
			for(DilithiumParameterSpec spec : specs) {
				Timings timing = timings.get(spec);
				
				// Generate
				KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium");
				kpg.initialize(spec, sr);
				
				long start = System.currentTimeMillis();
				KeyPair kp = kpg.generateKeyPair();
				long end = System.currentTimeMillis();
				if(!warmingup) {
					timing.generate += end - start;
				}
				
				// Sign
				Signature sig = Signature.getInstance("Dilithium");
				sig.initSign(kp.getPrivate());
				sig.update("Joy!".getBytes());
				start = System.currentTimeMillis();
				byte[] signature = sig.sign();
				end = System.currentTimeMillis();
				if(!warmingup) {
					timing.sign += end - start;
				}
		
				// Verify
				sig.initVerify(kp.getPublic());
				sig.update("Joy!".getBytes());
				start = System.currentTimeMillis();
				assertTrue(sig.verify(signature));
				end = System.currentTimeMillis();
				if(!warmingup) {
					timing.verify += end - start;
				}
			}
		}
		final int iterations = CNT - WARMUP;
		System.out.println("Iterations (ex warmup): " + iterations);
		for(DilithiumParameterSpec s : specs) {
			Timings t = timings.get(s);
			double gen = t.generate;
			gen /= iterations;
			
			double sign = t.sign;
			sign /= iterations; 

			double verify = t.verify;
			verify /= iterations;
			
			System.out.println("Level: " + s);
			System.out.println("Generate: " + gen);
			System.out.println("Sign: " + sign);
			System.out.println("Verify: " + verify);
		}
	}
	
	public static void main(String[] args) throws Exception {
		PerfTest pt = new PerfTest();
		pt.test();
	}
}
