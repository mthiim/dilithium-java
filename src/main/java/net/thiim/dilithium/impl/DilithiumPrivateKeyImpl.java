package net.thiim.dilithium.impl;

import net.thiim.dilithium.interfaces.DilithiumParameterSpec;
import net.thiim.dilithium.interfaces.DilithiumPrivateKey;

public class DilithiumPrivateKeyImpl implements DilithiumPrivateKey {
	private static final long serialVersionUID = 1L;
	private final byte[] rho;
	private final byte[] tr;
	private final byte[] K;
	private final PolyVec s1;
	private final PolyVec s2;
	private final PolyVec t0;
	private final PolyVec s1Hat;
	private final PolyVec s2Hat;
	private final PolyVec t0Hat;
	private final DilithiumParameterSpec spec;
	private final byte[] prvbytes;
	private final PolyVec[] A;

	public DilithiumPrivateKeyImpl(DilithiumParameterSpec spec, byte[] rho, byte[] K, byte[] tr, PolyVec s1, PolyVec s2, PolyVec t0, byte[] prvbytes,
			                       PolyVec[] A, PolyVec s1Hat, PolyVec s2Hat, PolyVec t0Hat) {
		this.rho = rho;
		this.tr = tr;
		this.K = K;
		this.s1 = s1;
		this.s2 = s2;
		this.t0 = t0;
		this.spec = spec;
		this.prvbytes = prvbytes;
		this.A = A;
		this.s1Hat = s1Hat;
		this.s2Hat = s2Hat;
		this.t0Hat = t0Hat;
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
		return prvbytes;
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
	public byte[] getTr() {
		return tr;
	}

	@Override
	public byte[] getK() {
		return K;
	}

	@Override
	public PolyVec getS1() {
		return s1;
	}

	@Override
	public PolyVec getS2() {
		return s2;
	}
	
	@Override
	public PolyVec getT0() {
		return t0;
	}

	public PolyVec[] getA() {
		return A;
	}

	@Override
	public PolyVec getS1Hat() {
		return s1Hat;
	}

	@Override
	public PolyVec getS2Hat() {
		return s2Hat;
	}

	@Override
	public PolyVec getT0Hat() {
		return t0Hat;
	}
}
