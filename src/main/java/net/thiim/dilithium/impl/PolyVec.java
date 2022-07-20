package net.thiim.dilithium.impl;

import java.util.Arrays;
import java.util.stream.IntStream;

public class PolyVec {
	Poly[] poly; 
	public PolyVec(int sz)
	{
		this.poly = new Poly[sz];
	}
	
	private PolyVec() 
	{
	}	
	
	public static PolyVec randomVec(byte[] rho, int eta, int length, int nonce) {
		PolyVec pv = new PolyVec(length);		
		for (int i = 0; i < length; i++) {
			pv.poly[i] = Poly.genRandom(rho, eta, nonce++);
		}
		return pv;
	}
	
	public static PolyVec randomVecGamma1(byte[] seed, int length, int gamma1, int nonce) {
		PolyVec z = new PolyVec(length);
		for (int i = 0; i < length; i++) {
			z.poly[i] = Poly.genRandomGamma1(seed, length * nonce + i, Dilithium.N, gamma1);
		}
		return z;
	}


	public PolyVec ntt() {
		PolyVec z = new PolyVec();
		z.poly = Arrays.stream(poly).map(Poly::ntt).toArray(Poly[]::new);
		return z;
	}
	
	public void reduce() {
		Arrays.stream(poly).forEach(Poly::reduce);
	}
	
	public PolyVec[] decompose(final int gamma2) {
		PolyVec[] res = new PolyVec[2];
		res[0] = new PolyVec(length());
		res[1] = new PolyVec(length());
		for (int i = 0; i < length(); i++) {
			Poly[] r = poly[i].decompose(gamma2);
			res[0].poly[i] = r[0];
			res[1].poly[i] = r[1];
		}
		return res;
	}

	
	public void invnttTomont() {
		Arrays.stream(poly).forEach(Poly::invnttTomont);
	}
	
	public PolyVec add(PolyVec other) {
		PolyVec res = new PolyVec();
		res.poly = IntStream.range(0, poly.length)
	                        .mapToObj(i -> poly[i].add(other.poly[i]))
	                        .toArray(Poly[]::new);		
		return res;
	}
	
	public PolyVec sub(PolyVec other) {
		PolyVec res = new PolyVec();
		res.poly = IntStream.range(0, poly.length)
	                        .mapToObj(i -> poly[i].sub(other.poly[i]))
	                        .toArray(Poly[]::new);		
		return res;
	}

	
	public void caddq() {
		Arrays.stream(poly).forEach(Poly::caddq);
	}
	
	public PolyVec shift() {
		PolyVec res = new PolyVec();
		res.poly = Arrays.stream(poly).map(Poly::shiftl).toArray(Poly[]::new);
		return res;
	}
	
	public PolyVec[] powerRound() {
		PolyVec[] res = new PolyVec[2];
		res[0] = new PolyVec(length());
		res[1] = new PolyVec(length());
		for (int i = 0; i < poly.length; i++) {
			Poly[] r = poly[i].powerRound();
			res[0].poly[i] = r[0];
			res[1].poly[i] = r[1];
		}
		return res;
	}
	
	public PolyVec pointwiseMontgomery(Poly u) {
		PolyVec r = new PolyVec();
		r.poly = Arrays.stream(poly).map(x -> u.pointwiseMontgomery(x)).toArray(Poly[]::new);
		return r;
	}
	
	public PolyVec mulMatrixPointwiseMontgomery(PolyVec[] M) {
		PolyVec pv = new PolyVec(M.length);		
		for (int i = 0; i < M.length; i++) {
			pv.poly[i] = pointwiseAccMontgomery(M[i], this);
		}
		return pv;
	}	

	private Poly pointwiseAccMontgomery(PolyVec u, PolyVec v) {
		Poly w = u.poly[0].pointwiseMontgomery(v.poly[0]);
		for (int i = 1; i < v.length(); i++) {
			Poly t = u.poly[i].pointwiseMontgomery(v.poly[i]);
			w = w.add(t);
		}
		return w;
	}

	public int length() {
		return poly.length;
	}
	
	public boolean chknorm(int bound) {	
		for(Poly p : poly) {
			if (p.chknorm(bound)) {
				return true;
			}
		}
		return false;
	}
}
