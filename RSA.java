import java.math.BigInteger;
import java.util.Random;

class RSA {

	public BigInteger e;
	public BigInteger d;
	public BigInteger N;

	public RSA() {
		key_generation(25);
	}

	public static BigInteger genPrime(int n) {

		BigInteger nPrime = BigInteger.probablePrime(n, new Random());

		return nPrime;
	}

	public static BigInteger modexp(BigInteger a, BigInteger b, BigInteger n) {
		BigInteger c;

		c = a.modPow(b, n);
		return c;
	}

	public String correctDecrypt(String m, BigInteger d, BigInteger n) {
		String[] list = m.split(" ");
		String res = "";
		for (String s : list) {
			BigInteger t = new BigInteger(s);
			t = decrypt(t, d, n);
			res += getCharForNumber(t);
		}
		return res;
	}

	public BigInteger decrypt(BigInteger c, BigInteger private_key, BigInteger decrypt_N) {
		BigInteger m = c.modPow(private_key, decrypt_N);
		return m;
	}

	public String correctEncrypt(String messageToEncrypt, BigInteger key, BigInteger n) {
		String returnMessage = "";
		for (char c : messageToEncrypt.toCharArray()) {
			BigInteger cBigInt = BigInteger.valueOf((int) c);
			BigInteger encryptedCBigInt = cBigInt.modPow(key, n);
			returnMessage += encryptedCBigInt + " ";
		}
		return returnMessage.trim();
	}

	public void key_generation(int n) {
		BigInteger p, q, bi1, bi2, Phi;

		p = genPrime(n);

		do {
			q = genPrime(n);
		} while (p.equals(q));

		N = p.multiply(q);

		bi1 = new BigInteger("1");
		bi2 = new BigInteger("-1");

		Phi = (p.subtract(bi1).multiply(q.subtract(bi1)));

		do {
			e = new BigInteger(n, new Random());
			if (e.gcd(Phi).equals(bi1) && e.compareTo(Phi) < 0 && !e.equals(bi1))
				break;
		} while (true);

		d = modexp(e, bi2, Phi);

	}

	private BigInteger getValueForChar(char c) {
		return BigInteger.valueOf((int) c);
	}

	@SuppressWarnings("unused")
	private String getCharForNumber(BigInteger i) {

		String r = "";

		if (i.compareTo(BigInteger.valueOf(127)) <= 0) {
			char t = (char) (i.intValue());
			return Character.toString(t);
		}

		return i.toString();
	}
}