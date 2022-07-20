package net.thiim.dilithium.interfaces;

import java.security.spec.AlgorithmParameterSpec;

import net.thiim.dilithium.impl.Dilithium;

public class DilithiumParameterSpec implements AlgorithmParameterSpec {
	public final int k;
	public final int l;
	public final int gamma1;
	public final int gamma2;
	public final int tau;
	public final int d;
	public final int chalentropy;
	public final int eta;
	public final int beta;
	public final int omega;
	public final String name;
	private DilithiumParameterSpec(String name, int k, int l, int gamma1, int gamma2, int tau, int d, int chalentropy, int eta, int beta, int omega)
	{
		this.name = name;
		this.k = k;
		this.l = l;
		this.gamma1 = gamma1;
		this.gamma2 = gamma2;
		this.tau = tau;
		this.d = d;
		this.chalentropy = chalentropy;
		this.eta = eta;
		this.beta = beta;
		this.omega = omega;
	}
	
	public final static DilithiumParameterSpec LEVEL2 = new DilithiumParameterSpec("Dilithium level 2 parameters", 4, 4, 1 << 17, (Dilithium.Q-1)/88, 39, 13, 192, 2, 78, 80);
	public final static DilithiumParameterSpec LEVEL3 = new DilithiumParameterSpec("Dilithium level 3 parameters", 6, 5, 1 << 19, (Dilithium.Q-1)/32, 49, 13, 225, 4, 196, 55);
	public final static DilithiumParameterSpec LEVEL5 = new DilithiumParameterSpec("Dilithium level 5 parameters", 8, 7, 1 << 19, (Dilithium.Q-1)/32, 60, 13, 257, 2, 120, 75);
	
	public static DilithiumParameterSpec getSpecForSecurityLevel(int level)
	{
		switch(level) {
		case 2:
			return LEVEL2;
		case 3:
			return LEVEL3;
		case 5:
			return LEVEL5;
			
		default:
			throw new UnsupportedOperationException("Unsupported level: " + level);
		
		}
	}

	@Override
	public String toString() {
		return name;
	}
}
