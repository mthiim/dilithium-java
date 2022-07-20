package net.thiim.dilithium.impl;

import net.thiim.dilithium.interfaces.DilithiumParameterSpec;
import net.thiim.dilithium.interfaces.DilithiumPublicKey;

public class DilithiumPublicKeyImpl implements DilithiumPublicKey {
	private static final long serialVersionUID = 1L;
	private final byte[] rho;
	private final PolyVec t1;
	private final PolyVec[] A;
	private final DilithiumParameterSpec spec;
	private final byte[] pubbytes;

	public DilithiumPublicKeyImpl(DilithiumParameterSpec spec, byte[] rho, PolyVec t1, byte[] pubbytes, PolyVec[] A) {
		this.t1 = t1;
		this.rho = rho;
		this.spec = spec;
		this.pubbytes = pubbytes;
		this.A = A;
	}

	@Override
	public String getAlgorithm() {
		return "Dilithium";
	}

	@Override
	public String getFormat() {
		return "RAW";
	}

	@Override
	public byte[] getEncoded() {
		return pubbytes;
	}

	@Override
	public DilithiumParameterSpec getSpec() {
		return spec;
	}

	@Override
	public byte[] getRho() {
		return rho;
	}

	@Override
	public PolyVec getT1() {
		return t1;
	}

	public PolyVec[] getA() {
		return A;
	}
}
