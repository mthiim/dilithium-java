package net.thiim.dilithium.impl;

import java.security.KeyPair;

import org.bouncycastle.crypto.digests.SHAKEDigest;

import net.thiim.dilithium.interfaces.DilithiumParameterSpec;
import net.thiim.dilithium.interfaces.DilithiumPrivateKey;
import net.thiim.dilithium.interfaces.DilithiumPublicKey;

public class Dilithium {
	public final static int N = 256;
	public final static int Q = 8380417;
	public final static int QINV = 58728449; // q^(-1) mod 2^32
	public final static int D = 13;

	public final static int POLYT0_PACKEDBYTES = 416;
	public final static int POLYT1_PACKEDBYTES = 320;
	public final static int SEEDBYTES = 32;
	public final static int CRHBYTES = 32;
	public final static int SHAKE128_RATE = 168;
	public final static int SHAKE256_RATE = 136;
	public final static int STREAM128_BLOCKBYTES = Dilithium.SHAKE128_RATE;
	public final static int STREAM256_BLOCKBYTES = SHAKE256_RATE;
	public final static int POLY_UNIFORM_GAMMA1_NBLOCKS = ((576 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES);
	public final static int zetas[] = new int[] { 0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
	1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900,
	3585928, -549488, -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237, -19422,
	4010497, 280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
	-3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694, -3821735,
	3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
	-3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221, -1257611, 1939314, -4083598,
	-1000202, -3190144, -3157330, -3632928, 126922, 3412210, -983419, 2147896, 2715295, -2967645, -3693493,
	-411027, -2477047, -671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383,
	264944, 508951, 3097992, 44288, -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356,
	-210977, 759969, -1316856, 189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
	1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
	3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181, -3520352, -3759364,
	-1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500, -655327, -3122442,
	2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297, 286988, -2437823, 4108315, 3437287,
	-3342277, 1735879, 203044, 2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974,
	-3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970, -1333058, 1237275, -3318210,
	-1430225, -451100, 1312455, 3306115, -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191,
	2235880, 3406031, -542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608,
	2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
	1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078, -426683,
	1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036, -2235985, -420899, -2286327,
	183443, -976891, 1612842, -3545687, -554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154,
	1976782 };
	public static final int MUBYTES = 64;


	public static KeyPair generateKeyPair(DilithiumParameterSpec spec, byte[] seed) {
		byte[] zeta = seed;

		byte[] o = Utils.getSHAKE256Digest(2*32+64, zeta);		
		byte[] rho = new byte[32];
		byte[] rhoprime = new byte[64];
		byte[] K = new byte[32];

		System.arraycopy(o, 0, rho, 0, 32);
		System.arraycopy(o, 32, rhoprime, 0, 64);
		System.arraycopy(o, 96, K, 0, 32);

		PolyVec s1 = PolyVec.randomVec(rhoprime, spec.eta, spec.l, 0);
		PolyVec s2 = PolyVec.randomVec(rhoprime, spec.eta, spec.k, spec.l);

		// Generate A
		PolyVec[] A = expandA(rho, spec.k, spec.l);

		PolyVec s1hat = s1.ntt();
		PolyVec t1 = s1hat.mulMatrixPointwiseMontgomery(A);
		t1.reduce();
		t1.invnttTomont();

		t1 = t1.add(s2);
		t1.caddq();

		PolyVec[] res = t1.powerRound();
		byte[] pubbytes = PackingUtils.packPubKey(rho, res[1]);

		byte[] tr = Utils.crh(pubbytes);

		byte[] prvbytes = PackingUtils.packPrvKey(spec.eta, rho, tr, K, res[0], s1, s2);
		
		PolyVec s2hat = s2.ntt();
		PolyVec t0hat = res[0].ntt();
		
		DilithiumPrivateKeyImpl prv = new DilithiumPrivateKeyImpl(spec, rho, K, tr, s1, s2, res[0], prvbytes, A, s1hat, s2hat, t0hat);
		DilithiumPublicKeyImpl pub = new DilithiumPublicKeyImpl(spec, rho, res[1], pubbytes, A);
		return new KeyPair(pub, prv);
	}
	
	public static byte[] sign(DilithiumPrivateKey prv, byte[] M) {
		DilithiumParameterSpec spec = prv.getSpec();

		final int CRYPTO_BYTES = Utils.getSigLength(spec);

		byte[] sig = new byte[CRYPTO_BYTES];
		
		PolyVec[] A;
		if(prv instanceof DilithiumPrivateKeyImpl) {
			A = ((DilithiumPrivateKeyImpl)prv).getA();
		}
		else {
			A = expandA(prv.getRho(), spec.k, spec.l);	
		}

		
		byte[] conc = Utils.concat(prv.getTr(), M);
		byte[] mu = Utils.mucrh(conc);
		conc = Utils.concat(prv.getK(), mu);
		byte[] rhoprime = Utils.mucrh(conc);

		PolyVec s1, s2, t0;
		if(prv instanceof DilithiumPrivateKeyImpl) {
			A = ((DilithiumPrivateKeyImpl)prv).getA();
			s1 = prv.getS1Hat();
			s2 = prv.getS2Hat();
			t0 = prv.getT0Hat();
		}
		else {
			s1 = prv.getS1().ntt();
			s2 = prv.getS2().ntt();
			t0 = prv.getT0().ntt();
		}
		

		int kappa = 0;
		for (;;) {
			PolyVec y = PolyVec.randomVecGamma1(rhoprime, spec.l, spec.gamma1, kappa++);
			PolyVec z = y.ntt();
			PolyVec w = z.mulMatrixPointwiseMontgomery(A);
			w.reduce();
			w.invnttTomont();
			w.caddq();
			PolyVec[] res = w.decompose(spec.gamma2);
			PackingUtils.packw1(spec.gamma2, res[1], sig);

			SHAKEDigest s = new SHAKEDigest(256);
			s.update(mu, 0, mu.length);
			s.update(sig, 0, res[1].length() * PackingUtils.getPolyW1PackedBytes(spec.gamma2));
			s.doOutput(sig, 0, SEEDBYTES);

			Poly cp = generateChallenge(spec.tau, sig);
			cp = cp.ntt();
			z = s1.pointwiseMontgomery(cp);
			z.invnttTomont();
			z = z.add(y);
			z.reduce();
			if (z.chknorm(spec.gamma1 - spec.beta)) {
				continue;
			}
			PolyVec h = s2.pointwiseMontgomery(cp);
			h.invnttTomont();
			PolyVec w0 = res[0].sub(h);
			w0.reduce();
			if (w0.chknorm(spec.gamma2 - spec.beta)) {
				continue;
			}

			h = t0.pointwiseMontgomery(cp);
			h.invnttTomont();
			h.reduce();
			if (h.chknorm(spec.gamma2)) {
				continue;
			}

			w0 = w0.add(h);
			w0.caddq();

			Hints hints = makeHints(spec.gamma2, w0, res[1]);
			if (hints.cnt > spec.omega) {
				continue;
			}

			PackingUtils.packSig(spec.gamma1, spec.omega, sig, sig, z, hints.v);
			return sig;
		}
	}
	
	public static boolean verify(DilithiumPublicKey pk, byte[] sig, byte[] M) {
		DilithiumParameterSpec spec = pk.getSpec();
		int CRYPTO_BYTES = Utils.getSigLength(spec);

		if (sig.length != CRYPTO_BYTES) {
			throw new RuntimeException("Bad signature");
		}

		PolyVec t1 = pk.getT1();

		int off = 0;
		byte[] c = new byte[SEEDBYTES];
		System.arraycopy(sig, 0, c, 0, SEEDBYTES);
		off += SEEDBYTES;

		PolyVec z = new PolyVec(spec.l);		
		for (int i = 0; i < spec.l; i++) {
			z.poly[i] = PackingUtils.zunpack(spec.gamma1, sig, off);
			off += PackingUtils.getPolyZPackedBytes(spec.gamma1);
		}

		PolyVec h = new PolyVec(spec.k);
		int k = 0;
		for (int i = 0; i < h.length(); i++) {
			h.poly[i] = new Poly(N);

			if ((sig[off + spec.omega + i] & 0xFF) < k || (sig[off + spec.omega + i] & 0xFF) > spec.omega)
				throw new RuntimeException("Bad signature");

			for (int j = k; j < (sig[off + spec.omega + i] & 0xFF); j++) {
				/* Coefficients are ordered for strong unforgeability */
				if (j > k && (sig[off + j] & 0xFF) <= (sig[off + j - 1] & 0xFF))
					throw new RuntimeException("Bad signature");
				h.poly[i].coef[sig[off + j] & 0xFF] = 1;
			}

			k = (sig[off + spec.omega + i] & 0xFF);
		}

		
		for (int j = k; j < spec.omega; j++) {
			if (sig[off + j] != 0) {
				throw new IllegalArgumentException("Invalid signature");
			}
		}
		
		if (z.chknorm(spec.gamma1 - spec.beta)) {
			throw new RuntimeException("Bad signature");
		}

		byte[] mu = Utils.crh(pk.getEncoded());
		mu = Utils.getSHAKE256Digest(MUBYTES,  mu, M);

		Poly cp = generateChallenge(spec.tau, c);
		
		PolyVec[] A;
		if(pk instanceof DilithiumPublicKeyImpl) {
			A = ((DilithiumPublicKeyImpl)pk).getA();
		}
		else {
			A = expandA(pk.getRho(), spec.k, spec.l);	
		}
		z = z.ntt();
		PolyVec w = z.mulMatrixPointwiseMontgomery(A);

		cp = cp.ntt();
		t1 = t1.shift();
		t1 = t1.ntt();

		t1 = t1.pointwiseMontgomery(cp);
		w = w.sub(t1);
		w.reduce();
		w.invnttTomont();		
		w.caddq();
		
		w = useHint(spec.gamma2, w, h);

		byte[] buf = new byte[PackingUtils.getPolyW1PackedBytes(spec.gamma2) * w.length()];
		PackingUtils.packw1(spec.gamma2, w, buf);
		
		byte[] c2 = Utils.getSHAKE256Digest(SEEDBYTES,  mu, buf);
		for (int i = 0; i < SEEDBYTES; i++) {
			if (c[i] != c2[i]) {
				return false;
			}
		}
		return true;
	}

	static PolyVec[] expandA(byte[] rho, int k, int l) {
		PolyVec[] A = new PolyVec[k];		
		for (int i = 0; i < k; i++) {
			A[i] = new PolyVec(l);
			for (int j = 0; j < l; j++) {
				A[i].poly[j] = Poly.genUniformRandom(rho, (i << 8) + j);
			}
		}
		return A;
	}

	private static PolyVec useHint(int gamma2, PolyVec u, PolyVec h) 
	{
		PolyVec res = new PolyVec(u.poly.length);
		for (int i = 0; i < res.length(); i++) {
			res.poly[i] = useHint(gamma2, u.poly[i], h.poly[i]);
		}
		return res;
	}

	private static Poly useHint(int gamma2, Poly u, Poly h) {
		Poly res = new Poly(N);
		for (int i = 0; i < N; i++) {
			res.coef[i] = useHint(gamma2, u.coef[i], h.coef[i]);
		}
		return res;
	}

	private static int useHint(int gamma2, int a, int hint) {
		int a0, a1;

		a1 = (a + 127) >> 7;
		if (gamma2 == (Q - 1) / 32) {
			a1 = (a1 * 1025 + (1 << 21)) >> 22;
			a1 &= 15;

		} else if (gamma2 == (Q - 1) / 88) {
			a1 = (a1 * 11275 + (1 << 23)) >> 24;
			a1 ^= ((43 - a1) >> 31) & a1;
		} else {
			throw new RuntimeException("Invalid gamma2: " + gamma2);
		}
		a0 = a - a1 * 2 * gamma2;
		a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;

		if (hint == 0) {
			return a1;
		}

		if (gamma2 == (Q - 1) / 32) {
			if (a0 > 0)
				return (a1 + 1) & 15;
			else
				return (a1 - 1) & 15;
		} else if (gamma2 == (Q - 1) / 88) {
			if (a0 > 0)
				return (a1 == 43) ? 0 : a1 + 1;
			else
				return (a1 == 0) ? 43 : a1 - 1;

		} else {
			throw new RuntimeException("Invalid gamma2: " + gamma2);
		}
	}

	private static class Hints {
		PolyVec v;
		int cnt;
	}

	private static class Hint {
		Poly v;
		int cnt;
	}

	private static Hints makeHints(int gamma2, PolyVec v0, PolyVec v1) {
		Hints hints = new Hints();
		hints.v = new PolyVec(v0.length());

		for (int i = 0; i < v0.length(); i++) {
			Hint hint = polyMakeHint(gamma2, v0.poly[i], v1.poly[i]);
			hints.cnt += hint.cnt;
			hints.v.poly[i] = hint.v;
		}
		return hints;

	}

	private static Hint polyMakeHint(int gamma2, Poly a, Poly b) {
		Hint hint = new Hint();
		hint.v = new Poly(N);
		for (int i = 0; i < N; i++) {
			hint.v.coef[i] = makeHint(gamma2, a.coef[i], b.coef[i]);
			hint.cnt += hint.v.coef[i];
		}
		return hint;

	}

	private static int makeHint(int gamma2, int a0, int a1) {
		if (a0 <= gamma2 || a0 > Q - gamma2 || (a0 == Q - gamma2 && a1 == 0))
			return 0;

		return 1;
	}

	private static Poly generateChallenge(int tau, byte[] seed) {
		Poly pre = new Poly(N);
		int b, pos;
		long signs;
		byte[] buf = new byte[SHAKE256_RATE];

		SHAKEDigest s = new SHAKEDigest(256);
		s.update(seed, 0, SEEDBYTES);
		s.doOutput(buf, 0, buf.length);

		signs = 0;
		for (int i = 0; i < 8; i++)
			signs |= (long) (buf[i] & 0xFF) << 8 * i;
		pos = 8;

		for (int i = N - tau; i < N; ++i) {
			do {
				if (pos >= SHAKE256_RATE) {
					s.doOutput(buf, 0, buf.length);
					pos = 0;
				}

				b = (buf[pos++] & 0xFF);
			} while (b > i);
			pre.coef[i] = pre.coef[b];
			pre.coef[b] = (int) (1 - 2 * (signs & 1));
			signs >>= 1;
		}
		return pre;
	}
}
