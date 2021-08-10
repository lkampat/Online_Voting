import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Random;
import java.util.Map.Entry;
import java.util.ArrayList;
import java.util.List;

public class CLA {
	RSA rsa = new RSA();
	String serverName = "localhost";
	
	static HashMap<String , BigInteger> allUserValNos = new HashMap<String, BigInteger>();
	static HashMap<String, String> allUserInfo = new HashMap<String, String>();
	static HashMap<String, BigInteger> allUserE = new HashMap<String, BigInteger>();
	static HashMap<String, BigInteger> allUserN = new HashMap<String, BigInteger>();

	static List<String> votedVoters = new ArrayList<>();
	
	static BigInteger ctfE;
	static BigInteger ctfN;
	static int ctfPort = 8101;
	static int ctfPort2 = 9101;
	static Socket ctfSocket;
	static ServerSocket ctfServersocket;

	static BigInteger claE;
	static BigInteger claD;
	static BigInteger claN;
	String claPu;	

	static BigInteger voterE;
	static BigInteger voterN;
	static int voterPort= 7101;
	private Socket voterSocket;
	private ServerSocket voterServersocket;

	Boolean stop = false;

	String rsaKey = rsa.e + "," + rsa.N;
	HashMap<String, String> Login = new HashMap<String, String>();



	public BigInteger[] readKeys(String fileName) {
		BigInteger keyValues[] = new BigInteger[2];
		String line = null;
		StringBuilder sb = new StringBuilder();

		try {
			FileReader fileReader = new FileReader(fileName);
			BufferedReader br = new BufferedReader(fileReader);

			while ((line = br.readLine()) != null) {
				String[] fileKeys = line.split(",");

				keyValues[0] = new BigInteger(fileKeys[0]);
				keyValues[1] = new BigInteger(fileKeys[1]);
			}
			br.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return keyValues;
	}



	private void readUsernameAndPassword() {		
		String fileName = "UserInfo.txt";
		String line = null;
		StringBuilder sb = new StringBuilder();

		try {
			FileReader fileReader = new FileReader(fileName);
			BufferedReader br = new BufferedReader(fileReader);

			while ((line = br.readLine()) != null) {
				String[] userInfo = line.split(",");

				allUserInfo.put(userInfo[0], userInfo[1]);
			}
			br.close();

		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}



	private void readVoterKeys() {		
		String fileName = "VoterPublic.txt";
		String line = null;
		StringBuilder sb = new StringBuilder();

		try {
			FileReader fileReader = new FileReader(fileName);
			BufferedReader br = new BufferedReader(fileReader);

			while ((line = br.readLine()) != null) {
				String[] userInfo = line.split(",");
				BigInteger tempUserE = new BigInteger(userInfo[1]);
				BigInteger tempUserN = new BigInteger(userInfo[2]);


				allUserE.put(userInfo[0], tempUserE);
				allUserN.put(userInfo[0], tempUserN);
			}
			br.close();

		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}



	private void readVoterValidationNos() {		
		String fileName = "CLAVoterValidationNos.txt";
		String line = null;
		StringBuilder sb = new StringBuilder();

		try {
			FileReader fileReader = new FileReader(fileName);
			BufferedReader br = new BufferedReader(fileReader);

			while ((line = br.readLine()) != null) {
				String[] userInfo = line.split(",");
				BigInteger tempUserVal = new BigInteger(userInfo[1]);

				allUserValNos.put(userInfo[0], tempUserVal);
			}
			br.close();

		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}



	public static void writeVoterValNo(String content) {
		String fileName = "CLAVoterValidationNos.txt";

		try {
			File file = new File(fileName);

			if (!file.exists()) {
				file.createNewFile();
			}

			FileWriter fw = new FileWriter(file, true);
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(content);
			bw.newLine();
			bw.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
	}



	private void readVotedVoters() {		
		String fileName = "VotedVoters.txt";
		String line = null;
		StringBuilder sb = new StringBuilder();

		try {

			File file = new File(fileName);

			if (!file.exists()) {
				file.createNewFile();
			}

			FileReader fileReader = new FileReader(fileName);
			BufferedReader br = new BufferedReader(fileReader);

			while ((line = br.readLine()) != null) {
				String thisVotedVoter = line;

				votedVoters.add(thisVotedVoter);
			}
			br.close();

		} catch (IOException ex) {
			ex.printStackTrace();
		}
	}



	public static void writeVotedVoters() {
		String fileName = "VotedVoters.txt";

		try {
			File file = new File(fileName);

			if (file.exists()) {
				file.delete();
			}

			file.createNewFile();

			FileWriter fw = new FileWriter(file, true);
			BufferedWriter bw = new BufferedWriter(fw);

			for (String voterName : votedVoters) {
			bw.write(voterName);
			bw.newLine();
			}

			bw.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
	}



	public void sendValNosToCtf() {
		try {
			System.out.println("Sending the CTF user validation numbers.");
			Socket ctf = new Socket(serverName, ctfPort);
			try {
				ObjectOutputStream out = new ObjectOutputStream(ctf.getOutputStream());
				List<String> valNoList = new ArrayList<>();
				for (String key : allUserValNos.keySet()) {
					BigInteger thisValNo = allUserValNos.get(key);
					String thisValNoString = thisValNo.toString();
					String thisValNoStringEncrypted = rsa.correctEncrypt(thisValNoString, ctfE, ctfN);

					System.out.println("\nvalidation number " + thisValNoString + " encyrpted to ");
					System.out.println(thisValNoStringEncrypted + " to send to CTF\n");
					valNoList.add(thisValNoStringEncrypted);
				}
				out.writeObject(valNoList);
			} catch (IOException e) {
				e.printStackTrace();
			}
			ctf.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}



	public void listenForVoters() {
		(new Thread() {
			@Override
			public void run() {
				try {
					voterServersocket = new ServerSocket(voterPort);
					System.out.println("Waiting for a voter to connect.");
					while (true && !stop) {
						Socket voter = voterServersocket.accept();
						System.out.println("\nVoter is connected.");

						ObjectInputStream in = new ObjectInputStream(voter.getInputStream());

						String voterMessage;
						voterMessage = (String) in.readObject();

						switch (voterMessage.substring(0, 1)) {
							case "0":
								System.out.println("Authorizing Voter.");
								String[] list = voterMessage.split(",");

								System.out.println("\nReceived encrypted username " + list[1] + " and encrypted password " + list[2]);

								String username = rsa.correctDecrypt(list[1], claD, claN);
								String password = rsa.correctDecrypt(list[2], claD, claN);

								System.out.println("Decrypted to username " + username + " and password " + password + "\n");

								Boolean authorized = false;
								String authorizationString = "";
								BigInteger voterValNo;

								try {
									ObjectOutputStream out = new ObjectOutputStream(voter.getOutputStream());
									if (allUserInfo.get(username).equals(password)) {
										authorized = true;
									}

									if (authorized) {
										if (allUserValNos.containsKey(username)) {
											voterValNo = allUserValNos.get(username);
											System.out.println("User already has a validation number: " + voterValNo.toString());
											String voterValNoEncrypted = rsa.correctEncrypt(voterValNo.toString(), allUserE.get(username), allUserN.get(username));
											authorizationString = "1," + voterValNoEncrypted;

											System.out.println("User's validation number sent to voter encrypted as " + voterValNoEncrypted);

										}
										else {
											voterValNo = new BigInteger(25, new Random());
											System.out.println("Assigning user a new validation number: " + voterValNo.toString());
											String voterValNoEncrypted = rsa.correctEncrypt(voterValNo.toString(), allUserE.get(username), allUserN.get(username));
											authorizationString = "2," + voterValNoEncrypted.toString();
											
											System.out.println("User's validation number sent to voter encrypted as " + voterValNoEncrypted);

											allUserValNos.put(username, voterValNo);
											writeVoterValNo(username + "," + voterValNo);
											sendValNosToCtf();
										}
									}
									else {
										authorizationString = "0, ";
										System.out.println("user has failed authorization. ");
									}
									

									out.writeObject(authorizationString);
									out.flush();

								} catch (IOException ex) {
									ex.printStackTrace();
								}
								break;
						}
					}
					voterSocket.close();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}).start();


		(new Thread() {
			@Override
			public void run() {

				try {
					ctfServersocket = new ServerSocket(ctfPort2);
					while (true && !stop) {
						Socket ctf = ctfServersocket.accept();
						System.out.println("\nCTF is sending Validation Number of user who voted.");

						ObjectInputStream in = new ObjectInputStream(ctf.getInputStream());

						String voterAndStatusEncrypted = (String) in.readObject();
						String voterAndStatus = rsa.correctDecrypt(voterAndStatusEncrypted, claD, claN);

						String[] voterAndStatusSplit = voterAndStatus.split(",");

						BigInteger recValNo = new BigInteger(voterAndStatusSplit[0]);

						for (Entry<String, BigInteger> userAndValNo : allUserValNos.entrySet()) {
							if (userAndValNo.getValue().compareTo(recValNo) == 0) {
								votedVoters.add(userAndValNo.getKey());
								System.out.println(userAndValNo.getKey() + " has voted.");
								writeVotedVoters();
							}
						}

				
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
				
				
			}

		}).start();
	}


	@SuppressWarnings("static-access")
	public static void main(String[] args) {
		CLA cla = new CLA();

		BigInteger ctfPu[] = cla.readKeys("CTFPublic.txt");
		ctfE = ctfPu[0];
		ctfN = ctfPu[1];

		BigInteger claPu[] = cla.readKeys("CLAPublic.txt");
		claE = claPu[0];

		BigInteger claPr[] = cla.readKeys("CLAPrivate.txt");
		claD = claPr[0];
		claN = claPr[1];

		cla.readVoterValidationNos();
		cla.readUsernameAndPassword();
		cla.readVoterKeys();
		cla.readVotedVoters();

		cla.sendValNosToCtf();

		cla.listenForVoters();
	}

}