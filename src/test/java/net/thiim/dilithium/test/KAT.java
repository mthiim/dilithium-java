package net.thiim.dilithium.test;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.LineNumberReader;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.PrivateKey;

import org.bouncycastle.util.encoders.Hex;

import net.thiim.dilithium.impl.Dilithium;
import net.thiim.dilithium.impl.PackingUtils;
import net.thiim.dilithium.impl.Utils;
import net.thiim.dilithium.interfaces.DilithiumParameterSpec;
import net.thiim.dilithium.interfaces.DilithiumPrivateKey;
import net.thiim.dilithium.interfaces.DilithiumPublicKey;
import net.thiim.dilithium.test.dbrg.PseudoRNG;

public class KAT {
	public static void main(String[] args) throws Exception {
		if(args.length != 3) {
			System.out.println("Use with parameters: <input-request-file> <output-response-file> <level>");
		}
		int level = Integer.parseInt(args[2]);
		DilithiumParameterSpec spec = DilithiumParameterSpec.getSpecForSecurityLevel(level);

		try(LineNumberReader lnr = new LineNumberReader(new FileReader(args[0]));
			PrintWriter pw = new PrintWriter(new FileWriter(args[1]))) {
			pw.println("# Dilithium" + level);
			pw.println("");

			String seed = null;
			String msg = null;
			String count = null;

			for (;;) {
				String line = lnr.readLine();
				if (line == null)
					break;
				if (line.startsWith("seed")) {
					seed = line.substring(7);
				} else if (line.startsWith("count")) {
					count = line.substring(8);
				} else if (line.startsWith("msg")) {
					msg = line.substring(6);
					doRun(pw, spec, count, seed, msg);
				}
			}
		}

	}

	private static void doRun(PrintWriter pw, DilithiumParameterSpec spec, String count, String seed, String msg) throws Exception {
		byte[] bseed = Hex.decodeStrict(seed);
		byte[] bmsg = Hex.decodeStrict(msg);
		PseudoRNG innerpr = new PseudoRNG(bseed, null, 256);
		byte[] innerseed = innerpr.generate(32);
		KeyPair kp = Dilithium.generateKeyPair(spec, innerseed);
		
		DilithiumPrivateKey sk = (DilithiumPrivateKey) kp.getPrivate();
		DilithiumPublicKey pk = (DilithiumPublicKey) kp.getPublic();

		byte[] sm = Dilithium.sign(sk, bmsg);
		if (!Dilithium.verify(pk, sm, bmsg)) {
			throw new Exception("Verification failed!");
		}

		byte[] conc = Utils.concat(sm, bmsg);

		pw.println("count = " + count);
		pw.println("seed = " + seed);
		pw.println("mlen = " + bmsg.length);
		pw.println("msg = " + msg);
		pw.println("pk = " + Hex.toHexString(pk.getEncoded()).toUpperCase());
		pw.println("sk = " + Hex.toHexString(sk.getEncoded()).toUpperCase());
		pw.println("smlen = " + conc.length);
		pw.println("sm = " + Hex.toHexString(conc).toUpperCase());
		pw.println("");
	}
}
