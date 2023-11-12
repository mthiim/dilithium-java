package net.thiim.dilithium.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.crypto.digests.SHAKEDigest;

import net.thiim.dilithium.interfaces.DilithiumParameterSpec;

public class Utils {
	public static void clear(byte[] x)
	{
		for(int i = 0; i < x.length; i++) {
			x[i] = 0;
		}
	}

	public static byte[] concat(byte[]... arr) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		for (byte[] x : arr) {
			try {
				baos.write(x);
			} catch (IOException e) {
				throw new RuntimeException("Unexpected error");
			}
		}
		return baos.toByteArray();
	}

	public static byte[] getSHAKE256Digest(int sz, byte[]... arr) {
		byte[] c = concat(arr);
		SHAKEDigest s = new SHAKEDigest(256);
		s.update(c, 0, c.length);
		byte[] o = new byte[sz];
		s.doOutput(o, 0, o.length);
		return o;
	}

	static byte[] crh(byte[] p) {
		return getSHAKE256Digest(Dilithium.CRHBYTES, p);
	}

	static byte[] mucrh(byte[] p) {
		return getSHAKE256Digest(Dilithium.MUBYTES, p);
	}

	public static int getSigLength(DilithiumParameterSpec spec) {
		return (Dilithium.SEEDBYTES + spec.l*PackingUtils.getPolyZPackedBytes(spec.gamma1) + spec.omega + spec.k);
	}

}
