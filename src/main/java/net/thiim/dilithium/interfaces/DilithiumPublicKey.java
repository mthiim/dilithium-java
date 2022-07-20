package net.thiim.dilithium.interfaces;

import java.security.PublicKey;

import net.thiim.dilithium.impl.Poly;
import net.thiim.dilithium.impl.PolyVec;

public interface DilithiumPublicKey extends PublicKey {
	public byte[] getRho();
	public PolyVec getT1();
	public DilithiumParameterSpec getSpec();
}
