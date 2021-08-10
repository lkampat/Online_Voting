import java.math.BigInteger;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;

public class Test {
	public static void main(String[] args) {
		
		for (String keyFileName: args) {
			RSA rsa = new RSA();
			System.out.println(rsa.e);
			System.out.println(rsa.d);
			System.out.println(rsa.N);

			String eString = rsa.e.toString();
			String dString = rsa.d.toString();
			String nString = rsa.N.toString();

			if (keyFileName.equals("CTF") || keyFileName.equals("CLA")) {
				try {
					File file = new File(keyFileName + "Public.txt");

					if (!file.exists()) {
						file.createNewFile();
					}

					FileWriter fw = new FileWriter(file,true);

					BufferedWriter bw = new BufferedWriter(fw);
					bw.write(eString);
					bw.write(",");
					bw.write(nString);
					bw.close();
				} catch (IOException e) {
					e.printStackTrace();
				}

				try {
					File file = new File(keyFileName + "Private.txt");

					if (!file.exists()) {
						file.createNewFile();
					}

					FileWriter fw = new FileWriter(file,true);

					BufferedWriter bw = new BufferedWriter(fw);
					bw.write(dString);
					bw.write(",");
					bw.write(nString);
					bw.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

			else {
				try {
					File file = new File("VoterPublic.txt");

					if (!file.exists()) {
						file.createNewFile();
					}

					FileWriter fw = new FileWriter(file,true);

					BufferedWriter bw = new BufferedWriter(fw);
					bw.write(keyFileName);
					bw.write(",");
					bw.write(eString);
					bw.write(",");
					bw.write(nString);
					bw.write("\n");
					bw.close();
				} catch (IOException e) {
					e.printStackTrace();
				}

				try {
					File file = new File("VoterPrivate.txt");

					if (!file.exists()) {
						file.createNewFile();
					}

					FileWriter fw = new FileWriter(file,true);

					BufferedWriter bw = new BufferedWriter(fw);
					bw.write(keyFileName);
					bw.write(",");
					bw.write(dString);
					bw.write(",");
					bw.write(nString);
					bw.write("\n");
					bw.close();
				} catch (IOException e) {
					e.printStackTrace();
				}

			}			
		}
	}
}