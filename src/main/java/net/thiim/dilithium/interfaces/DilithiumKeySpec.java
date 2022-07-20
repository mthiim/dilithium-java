package net.thiim.dilithium.interfaces;

import java.security.spec.KeySpec;

public class DilithiumKeySpec implements KeySpec {
	private byte[] bytes;
	private DilithiumParameterSpec paramSpec;
	public DilithiumKeySpec(DilithiumParameterSpec paramSpec, byte[] bytes)
	{
		this.bytes = bytes;
		this.paramSpec = paramSpec;
	}
	
	public byte[] getBytes()
	{
		return this.bytes;
	}
	
	public DilithiumParameterSpec getParameterSpec() {
		return paramSpec;
	}
}
