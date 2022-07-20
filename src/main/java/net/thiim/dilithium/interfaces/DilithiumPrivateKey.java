package net.thiim.dilithium.interfaces;

import java.security.PrivateKey;

import net.thiim.dilithium.impl.Poly;
import net.thiim.dilithium.impl.PolyVec;

public interface DilithiumPrivateKey extends PrivateKey {
	public DilithiumParameterSpec getSpec();
	public byte[] getRho();
	public byte[] getTr();
	public byte[] getK();
	public PolyVec getS1();
	public PolyVec getS2();
	public PolyVec getT0();
	public PolyVec getS1Hat();
	public PolyVec getS2Hat();
	public PolyVec getT0Hat();
}
