package net.thiim.dilithium.provider;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

import net.thiim.dilithium.impl.Dilithium;
import net.thiim.dilithium.interfaces.DilithiumPrivateKey;
import net.thiim.dilithium.interfaces.DilithiumPublicKey;

public class DilithiumSignature extends SignatureSpi {
	static enum Mode {
		VERIFY, SIGN;
	}
	
	private DilithiumPublicKey pubk;
	private DilithiumPrivateKey prvk;
	private ByteArrayOutputStream baos;
	
	private Mode mode;
	
	@Override
	protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {		
		if(!(publicKey instanceof DilithiumPublicKey)) {
			throw new IllegalArgumentException("Not a valid public key");
		}
		
		mode = Mode.VERIFY;
		pubk = (DilithiumPublicKey)publicKey;
		baos = new ByteArrayOutputStream();
	}

	@Override
	protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
		if(!(privateKey instanceof DilithiumPrivateKey)) {
			throw new IllegalArgumentException("Not a valid private key");
		}
		
		mode = Mode.SIGN;
		prvk = (DilithiumPrivateKey)privateKey;
		baos = new ByteArrayOutputStream();
	}

	@Override
	protected void engineUpdate(byte b) throws SignatureException {
		baos.write(b & 0xFF);		
	}

	@Override
	protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
		baos.write(b, off, len);		
	}

	@Override
	protected byte[] engineSign() throws SignatureException {
		if(mode != Mode.SIGN || baos == null || prvk == null) {
			throw new IllegalStateException("Not in signing mode");
		}
		byte[] M = baos.toByteArray();
		byte[] sig = Dilithium.sign(prvk, M);
		baos = new ByteArrayOutputStream();
		return sig;
	}

	@Override
	protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
		if(mode != Mode.VERIFY || baos == null || pubk == null) {
			throw new IllegalStateException("Not in verify mode");
		}
		byte[] M = baos.toByteArray();		
		boolean match = Dilithium.verify(pubk, sigBytes, M);
		baos = new ByteArrayOutputStream();
		return match;
	}

	@Override
	protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
		throw new UnsupportedOperationException("Not supported");
		
	}

	@Override
	protected Object engineGetParameter(String param) throws InvalidParameterException {
		throw new UnsupportedOperationException("Not supported");
	}
}
