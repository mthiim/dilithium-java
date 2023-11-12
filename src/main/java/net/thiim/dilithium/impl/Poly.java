package net.thiim.dilithium.impl;

import org.bouncycastle.crypto.digests.SHAKEDigest;

public class Poly {
	int[] coef;

	public Poly(int n) {
		this.coef = new int[n];
	}

	public Poly add(Poly other) {
		Poly res = new Poly(this.coef.length);
		for (int i = 0; i < coef.length; i++) {
			res.coef[i] = (coef[i] + other.coef[i]) % Dilithium.Q;
		}
		return res;
	}

	public Poly sub(Poly other) {
		Poly res = new Poly(this.coef.length);
		for (int i = 0; i < coef.length; i++) {
			res.coef[i] = (coef[i] - other.coef[i]) % Dilithium.Q;
		}
		return res;

	}

	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append("[");
		for (int i = 0; i < coef.length; i++) {
			if (i != 0) {
				sb.append(", ");
			}
			sb.append("" + coef[i]);
		}
		sb.append("]");
		return sb.toString();
	}

	public static Poly genRandom(byte[] rho, int eta, int nonce) {
		int POLY_UNIFORM_ETA_NBLOCKS;
		if (eta == 2) {
			POLY_UNIFORM_ETA_NBLOCKS = ((136 + Dilithium.STREAM256_BLOCKBYTES - 1) / Dilithium.STREAM256_BLOCKBYTES);
		} else if (eta == 4) {
			POLY_UNIFORM_ETA_NBLOCKS = ((227 + Dilithium.STREAM256_BLOCKBYTES - 1) / Dilithium.STREAM256_BLOCKBYTES);
		} else {
			throw new IllegalArgumentException("Illegal eta: " + eta);
		}

		int ctr;
		SHAKEDigest s = new SHAKEDigest(256);
		s.update(rho, 0, rho.length);

		byte[] non = new byte[2];
		non[0] = (byte) (nonce & 0xFF);
		non[1] = (byte) ((nonce >> 8) & 0xFF);
		s.update(non, 0, 2);

		byte[] bb = new byte[POLY_UNIFORM_ETA_NBLOCKS * Dilithium.STREAM256_BLOCKBYTES];
		s.doOutput(bb, 0, bb.length);

		Poly pre = new Poly(Dilithium.N);
		ctr = rej_eta(eta, pre.coef, 0, Dilithium.N, bb, bb.length);

		while (ctr < Dilithium.N) {
			s.doOutput(bb, 0, Dilithium.STREAM256_BLOCKBYTES);
			ctr += rej_eta(eta, pre.coef, ctr, Dilithium.N - ctr, bb, Dilithium.STREAM256_BLOCKBYTES);

		}
		return pre;

	}

	private static int rej_eta(int eta, int[] coef, int off, int len, byte[] buf, int buflen) {
		int ctr, pos;
		int t0, t1;

		ctr = pos = 0;
		if (eta == 2) {
			while (ctr < len && pos < buflen) {
				t0 = buf[pos] & 0x0F;
				t1 = (buf[pos++] >> 4) & 0x0F;
				if (t0 < 15) {
					t0 = t0 - (205 * t0 >>> 10) * 5;
					coef[off + ctr++] = 2 - t0;
				}
				if (t1 < 15 && ctr < len) {
					t1 = t1 - (205 * t1 >>> 10) * 5;
					coef[off + ctr++] = 2 - t1;
				}
			}
		} else {
			while (ctr < len && pos < buflen) {
				t0 = buf[pos] & 0x0F;
				t1 = (buf[pos++] >> 4) & 0x0F;
				if (t0 < 9)
					coef[off + ctr++] = 4 - t0;
				if (t1 < 9 && ctr < len)
					coef[off + ctr++] = 4 - t1;
			}
		}

		return ctr;
	}

	public Poly ntt() {
		Poly ret = new Poly(this.coef.length);
		for (int i = 0; i < this.coef.length; i++) {
			ret.coef[i] = this.coef[i];
		}
		int len, start, j, k;
		int zeta, t;

		k = 0;
		for (len = 128; len > 0; len >>= 1) {
			for (start = 0; start < Dilithium.N; start = j + len) {
				zeta = Dilithium.zetas[++k];
				for (j = start; j < start + len; ++j) {
					t = montgomery_reduce((long) zeta * ret.coef[j + len]);
					ret.coef[j + len] = ret.coef[j] - t;
					ret.coef[j] = ret.coef[j] + t;
				}
			}
		}
		return ret;
	}

	static int montgomery_reduce(long a) {
		int t;

		t = (int) (a * Dilithium.QINV);
		t = (int) (((a - ((long) t) * Dilithium.Q) >> 32) & 0xFFFFFFFF);
		return t;
	}

	public static Poly genUniformRandom(byte[] rho, int nonce) {
		final int POLY_UNIFORM_NBLOCKS = ((768 + Dilithium.STREAM128_BLOCKBYTES - 1) / Dilithium.STREAM128_BLOCKBYTES);
		int ctr, off;
		int buflen = POLY_UNIFORM_NBLOCKS * Dilithium.STREAM128_BLOCKBYTES;
		byte[] buf = new byte[buflen + 2];

		SHAKEDigest s = new SHAKEDigest(128);
		s.update(rho, 0, rho.length);

		byte[] non = new byte[2];
		non[0] = (byte) (nonce & 0xFF);
		non[1] = (byte) ((nonce >> 8) & 0xFF);
		s.update(non, 0, 2);
		s.doOutput(buf, 0, buflen);
		

		Poly pre = new Poly(Dilithium.N);
		ctr = rej_uniform(pre.coef, 0, Dilithium.N, buf, buflen);

		while (ctr < Dilithium.N) {
			off = buflen % 3;
			for (int i = 0; i < off; i++)
				buf[i] = buf[buflen - off + i];
			s.doOutput(buf, off, Dilithium.STREAM128_BLOCKBYTES);
			buflen = Dilithium.STREAM128_BLOCKBYTES + off;
			ctr += rej_uniform(pre.coef, ctr, Dilithium.N - ctr, buf, buflen);

		}
		return pre;

	}

	private static int rej_uniform(int[] coef, int off, int len, byte[] buf, int buflen) {
		int ctr, pos;
		int t;

		ctr = pos = 0;
		while (ctr < len && pos + 3 <= buflen) {
			t = (buf[pos++] & 0xFF);
			t |= ((int) buf[pos++] & 0xFF) << 8;
			t |= ((int) buf[pos++] & 0xFF) << 16;
			t &= 0x7FFFFF;

			if (t < Dilithium.Q)
				coef[off + ctr++] = t;
		}
		return ctr;
	}

	public Poly pointwiseMontgomery(Poly other) {
		Poly c = new Poly(Dilithium.N);
		for (int i = 0; i < Dilithium.N; i++) {
			c.coef[i] = montgomery_reduce(((long) (this.coef[i])) * other.coef[i]);
		}
		return c;

	}

	public void reduce() {
		for (int i = 0; i < Dilithium.N; i++) {
			coef[i] = reduce32(coef[i]);
		}
	}

	private static int reduce32(int a) {
		int t;
		t = (a + (1 << 22)) >> 23;
		t = a - t * Dilithium.Q;
		return t;
	}

	public void invnttTomont() {
		int start, len, j, k;
		int t, zeta;
		final int f = 41978; // mont^2/256

		k = 256;
		for (len = 1; len < Dilithium.N; len <<= 1) {
			for (start = 0; start < Dilithium.N; start = j + len) {
				zeta = -Dilithium.zetas[--k];
				for (j = start; j < start + len; ++j) {
					t = coef[j];
					coef[j] = t + coef[j + len];
					coef[j + len] = t - coef[j + len];
					coef[j + len] = montgomery_reduce(((long) zeta) * coef[j + len]);
				}
			}
		}

		for (j = 0; j < Dilithium.N; ++j) {
			coef[j] = montgomery_reduce(((long) f) * coef[j]);
		}
	}

	public void caddq() {
		for (int i = 0; i < coef.length; i++) {
			coef[i] = caddq(coef[i]);
		}

	}

	private int caddq(int a) {
		a += (a >> 31) & Dilithium.Q;
		return a;
	}

	public Poly[] powerRound() {
		Poly[] pr = new Poly[2];
		pr[0] = new Poly(Dilithium.N);
		pr[1] = new Poly(Dilithium.N);

		for (int i = 0; i < this.coef.length; i++) {
			int a = this.coef[i];
			pr[1].coef[i] = (a + (1 << (Dilithium.D - 1)) - 1) >> Dilithium.D;
			pr[0].coef[i] = a - (pr[1].coef[i] << Dilithium.D);
		}
		return pr;
	}

	public void t1pack(byte[] r, int off) {
		for (int i = 0; i < Dilithium.N / 4; i++) {
			r[5 * i + 0 + off] = (byte) ((coef[4 * i + 0] >>> 0));
			r[5 * i + 1 + off] = (byte) ((coef[4 * i + 0] >>> 8) | (coef[4 * i + 1] << 2));
			r[5 * i + 2 + off] = (byte) ((coef[4 * i + 1] >>> 6) | (coef[4 * i + 2] << 4));
			r[5 * i + 3 + off] = (byte) ((coef[4 * i + 2] >>> 4) | (coef[4 * i + 3] << 6));
			r[5 * i + 4 + off] = (byte) ((coef[4 * i + 3] >>> 2));
		}

	}

	public void etapack(int eta, byte[] buf, int off) {
		byte[] t = new byte[8];
		if (eta == 2) {
			for (int i = 0; i < Dilithium.N / 8; i++) {
				t[0] = (byte) (eta - this.coef[8 * i + 0]);
				t[1] = (byte) (eta - this.coef[8 * i + 1]);
				t[2] = (byte) (eta - this.coef[8 * i + 2]);
				t[3] = (byte) (eta - this.coef[8 * i + 3]);
				t[4] = (byte) (eta - this.coef[8 * i + 4]);
				t[5] = (byte) (eta - this.coef[8 * i + 5]);
				t[6] = (byte) (eta - this.coef[8 * i + 6]);
				t[7] = (byte) (eta - this.coef[8 * i + 7]);

				buf[off + 3 * i + 0] = (byte) ((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
				buf[off + 3 * i + 1] = (byte) ((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
				buf[off + 3 * i + 2] = (byte) ((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
			}

		} else if (eta == 4) {
			for (int i = 0; i < Dilithium.N / 2; i++) {
				t[0] = (byte) (eta - this.coef[2 * i + 0]);
				t[1] = (byte) (eta - this.coef[2 * i + 1]);
				buf[off + i] = (byte) (t[0] | (t[1] << 4));
			}
		} else {
			throw new IllegalArgumentException("Illegal eta: " + eta);
		}
	}

	public void t0pack(byte[] buf, int off) {
		int[] t = new int[8];

		for (int i = 0; i < Dilithium.N / 8; i++) {
			t[0] = (1 << (Dilithium.D - 1)) - this.coef[8 * i + 0];
			t[1] = (1 << (Dilithium.D - 1)) - this.coef[8 * i + 1];
			t[2] = (1 << (Dilithium.D - 1)) - this.coef[8 * i + 2];
			t[3] = (1 << (Dilithium.D - 1)) - this.coef[8 * i + 3];
			t[4] = (1 << (Dilithium.D - 1)) - this.coef[8 * i + 4];
			t[5] = (1 << (Dilithium.D - 1)) - this.coef[8 * i + 5];
			t[6] = (1 << (Dilithium.D - 1)) - this.coef[8 * i + 6];
			t[7] = (1 << (Dilithium.D - 1)) - this.coef[8 * i + 7];

			buf[off + 13 * i + 0] = (byte) (t[0]);
			buf[off + 13 * i + 1] = (byte) (t[0] >> 8);
			buf[off + 13 * i + 1] |= (byte) (t[1] << 5);
			buf[off + 13 * i + 2] = (byte) (t[1] >> 3);
			buf[off + 13 * i + 3] = (byte) (t[1] >> 11);
			buf[off + 13 * i + 3] |= (byte) (t[2] << 2);
			buf[off + 13 * i + 4] = (byte) (t[2] >> 6);
			buf[off + 13 * i + 4] |= (byte) (t[3] << 7);
			buf[off + 13 * i + 5] = (byte) (t[3] >> 1);
			buf[off + 13 * i + 6] = (byte) (t[3] >> 9);
			buf[off + 13 * i + 6] |= (byte) (t[4] << 4);
			buf[off + 13 * i + 7] = (byte) (t[4] >> 4);
			buf[off + 13 * i + 8] = (byte) (t[4] >> 12);
			buf[off + 13 * i + 8] |= (byte) (t[5] << 1);
			buf[off + 13 * i + 9] = (byte) (t[5] >> 7);
			buf[off + 13 * i + 9] |= (byte) (t[6] << 6);
			buf[off + 13 * i + 10] = (byte) (t[6] >> 2);
			buf[off + 13 * i + 11] = (byte) (t[6] >> 10);
			buf[off + 13 * i + 11] |= (byte) (t[7] << 3);
			buf[off + 13 * i + 12] = (byte) (t[7] >> 5);
		}

	}

	public static Poly genRandomGamma1(byte[] seed, int nonce, int N, int gamma1) {
		Poly pre = new Poly(N);
		byte[] buf = new byte[Dilithium.POLY_UNIFORM_GAMMA1_NBLOCKS * Dilithium.STREAM256_BLOCKBYTES];
		SHAKEDigest s = new SHAKEDigest(256);
		s.update(seed, 0, seed.length);

		byte[] non = new byte[2];
		non[0] = (byte) (nonce & 0xFF);
		non[1] = (byte) ((nonce >> 8) & 0xFF);
		s.update(non, 0, 2);
		s.doOutput(buf, 0, buf.length);

		if (gamma1 == (1 << 17)) {
			for (int i = 0; i < N / 4; i++) {
				pre.coef[4 * i + 0] = (buf[9 * i + 0] & 0xFF);
				pre.coef[4 * i + 0] |= (int) (buf[9 * i + 1] & 0xFF) << 8;
				pre.coef[4 * i + 0] |= (int) (buf[9 * i + 2] & 0xFF) << 16;
				pre.coef[4 * i + 0] &= 0x3FFFF;

				pre.coef[4 * i + 1] = (buf[9 * i + 2] & 0xFF) >> 2;
				pre.coef[4 * i + 1] |= (int) (buf[9 * i + 3] & 0xFF) << 6;
				pre.coef[4 * i + 1] |= (int) (buf[9 * i + 4] & 0xFF) << 14;
				pre.coef[4 * i + 1] &= 0x3FFFF;

				pre.coef[4 * i + 2] = (buf[9 * i + 4] & 0xFF) >> 4;
				pre.coef[4 * i + 2] |= (int) (buf[9 * i + 5] & 0xFF) << 4;
				pre.coef[4 * i + 2] |= (int) (buf[9 * i + 6] & 0xFF) << 12;
				pre.coef[4 * i + 2] &= 0x3FFFF;

				pre.coef[4 * i + 3] = (buf[9 * i + 6] & 0xFF) >> 6;
				pre.coef[4 * i + 3] |= (int) (buf[9 * i + 7] & 0xFF) << 2;
				pre.coef[4 * i + 3] |= (int) (buf[9 * i + 8] & 0xFF) << 10;
				pre.coef[4 * i + 3] &= 0x3FFFF;

				pre.coef[4 * i + 0] = gamma1 - pre.coef[4 * i + 0];
				pre.coef[4 * i + 1] = gamma1 - pre.coef[4 * i + 1];
				pre.coef[4 * i + 2] = gamma1 - pre.coef[4 * i + 2];
				pre.coef[4 * i + 3] = gamma1 - pre.coef[4 * i + 3];
			}

		} else if (gamma1 == (1 << 19)) {
			for (int i = 0; i < N / 2; i++) {
				pre.coef[2 * i + 0] = buf[5 * i + 0] & 0xFF;
				pre.coef[2 * i + 0] |= (buf[5 * i + 1] & 0xFF) << 8;
				pre.coef[2 * i + 0] |= (buf[5 * i + 2] & 0xFF) << 16;
				pre.coef[2 * i + 0] &= 0xFFFFF;

				pre.coef[2 * i + 1] = (buf[5 * i + 2] & 0xFF) >> 4;
				pre.coef[2 * i + 1] |= (buf[5 * i + 3] & 0xFF) << 4;
				pre.coef[2 * i + 1] |= (buf[5 * i + 4] & 0xFF) << 12;
				pre.coef[2 * i + 0] &= 0xFFFFF;

				pre.coef[2 * i + 0] = gamma1 - pre.coef[2 * i + 0];
				pre.coef[2 * i + 1] = gamma1 - pre.coef[2 * i + 1];
			}

		} else {
			throw new IllegalArgumentException("Invalid gamma1: " + gamma1);
		}
		return pre;
	}

	public Poly[] decompose(final int gamma2) {
		Poly[] pr = new Poly[2];
		pr[0] = new Poly(Dilithium.N);
		pr[1] = new Poly(Dilithium.N);

		for (int i = 0; i < this.coef.length; i++) {
			int a = this.coef[i];

			int a1 = (a + 127) >> 7;
		if (gamma2 == (Dilithium.Q - 1) / 32) {
			a1 = (a1 * 1025 + (1 << 21)) >> 22;
			a1 &= 15;

		} else if (gamma2 == (Dilithium.Q - 1) / 88) {
			a1 = (a1 * 11275 + (1 << 23)) >> 24;
			a1 ^= ((43 - a1) >> 31) & a1;
		} else {
			throw new IllegalArgumentException("Invalid gamma2: " + gamma2);
		}
		pr[0].coef[i] = a - a1 * 2 * gamma2;
		pr[0].coef[i] -= (((Dilithium.Q - 1) / 2 - pr[0].coef[i]) >> 31) & Dilithium.Q;
		pr[1].coef[i] = a1;
		}
		return pr;
	}

	public void w1pack(int gamma2, byte[] buf, int off) {
		if (gamma2 == (Dilithium.Q - 1) / 88) {
			for (int i = 0; i < Dilithium.N / 4; i++) {
				buf[off + 3 * i + 0] = (byte) this.coef[4 * i + 0];
				buf[off + 3 * i + 0] |= (byte) (this.coef[4 * i + 1] << 6);
				buf[off + 3 * i + 1] = (byte) (this.coef[4 * i + 1] >> 2);
				buf[off + 3 * i + 1] |= (byte) (this.coef[4 * i + 2] << 4);
				buf[off + 3 * i + 2] = (byte) (this.coef[4 * i + 2] >> 4);
				buf[off + 3 * i + 2] |= (byte) (this.coef[4 * i + 3] << 2);
			}

		} else if (gamma2 == (Dilithium.Q - 1) / 32) {
			for (int i = 0; i < Dilithium.N / 2; i++)
				buf[off + i] = (byte) (this.coef[2 * i + 0] | (this.coef[2 * i + 1] << 4));
		} else {
			throw new IllegalArgumentException("Invalid gamma2: " + gamma2);

		}
	}

	public boolean chknorm(int B) {
		int t;

		if (B > (Dilithium.Q - 1) / 8)
			return true;

		/*
		 * It is ok to leak which coefficient violates the bound since the probability
		 * for each coefficient is independent of secret data but we must not leak the
		 * sign of the centralized representative.
		 */
		for (int i = 0; i < Dilithium.N; i++) {
			/* Absolute value */
			t = coef[i] >> 31;
		t = coef[i] - (t & 2 * coef[i]);

		if (t >= B) {
			return true;
		}
		}

		return false;

	}

	public void zpack(int gamma1, byte[] sign, int off) {
		long[] t = new long[4];

		if (gamma1 == (1 << 17)) {
			for (int i = 0; i < Dilithium.N / 4; i++) {
				t[0] = (gamma1 - this.coef[4 * i + 0]) & 0xFFFFFFFFL;
				t[1] = (gamma1 - this.coef[4 * i + 1]) & 0xFFFFFFFFL;
				t[2] = (gamma1 - this.coef[4 * i + 2]) & 0xFFFFFFFFL;
				t[3] = (gamma1 - this.coef[4 * i + 3]) & 0xFFFFFFFFL;

				sign[off + 9 * i + 0] = (byte) t[0];
				sign[off + 9 * i + 1] = (byte) (t[0] >> 8);
				sign[off + 9 * i + 2] = (byte) (t[0] >> 16);
				sign[off + 9 * i + 2] |= (byte) (t[1] << 2);
				sign[off + 9 * i + 3] = (byte) (t[1] >> 6);
				sign[off + 9 * i + 4] = (byte) (t[1] >> 14);
				sign[off + 9 * i + 4] |= (byte) (t[2] << 4);
				sign[off + 9 * i + 5] = (byte) (t[2] >> 4);
				sign[off + 9 * i + 6] = (byte) (t[2] >> 12);
				sign[off + 9 * i + 6] |= (byte) (t[3] << 6);
				sign[off + 9 * i + 7] = (byte) (t[3] >> 2);
				sign[off + 9 * i + 8] = (byte) (t[3] >> 10);
			}

		} else if (gamma1 == (1 << 19)) {
			for (int i = 0; i < Dilithium.N / 2; i++) {
				t[0] = gamma1 - this.coef[2 * i + 0];
				t[1] = gamma1 - this.coef[2 * i + 1];

				sign[off + 5 * i + 0] = (byte) (t[0]);
				sign[off + 5 * i + 1] = (byte) (t[0] >> 8);
				sign[off + 5 * i + 2] = (byte) (t[0] >> 16);
				sign[off + 5 * i + 2] |= (byte) (t[1] << 4);
				sign[off + 5 * i + 3] = (byte) (t[1] >> 4);
				sign[off + 5 * i + 4] = (byte) (t[1] >> 12);
			}

		} else {
			throw new IllegalArgumentException("Invalid gamma1: " + gamma1);
		}
	}

	public Poly shiftl() {
		Poly pr = new Poly(Dilithium.N);
		for (int i = 0; i < Dilithium.N; i++)
			pr.coef[i] = (this.coef[i] << Dilithium.D);
		return pr;
	}
}
