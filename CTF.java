import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map.Entry;
import java.util.ArrayList;
import java.util.List;

public class CTF {
	RSA rsa = new RSA();
	String serverName = "localhost";

	static HashMap<String, BigInteger> allUserE = new HashMap<String, BigInteger>();
	static HashMap<String, BigInteger> allUserN = new HashMap<String, BigInteger>();
	static HashMap<BigInteger, BigInteger> voteRecord = new HashMap<BigInteger, BigInteger>();
	static HashMap<BigInteger, Integer> voteTally = new HashMap<BigInteger, Integer>();
	
	static BigInteger voterE;
	static BigInteger voterN;
	static int voterPort = 6101;	
	private Socket voterSocket;
	private ServerSocket voterServersocket;

	static BigInteger claE;
	static BigInteger claN;
	static int claPort = 8101;
	static int claPort2 = 9101;
	private ServerSocket claServersocket;
	private Socket claSocket;

	static BigInteger ctfE;
	static BigInteger ctfD;
	static BigInteger ctfN;



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



	private void countVote(String valNoAndVote, Socket voter) {
		String[] list = valNoAndVote.split(",");

		String encryptedValNo = list[1];
		String encryptedVote = list[2];

		String decryptedValNoString = rsa.correctDecrypt(encryptedValNo, ctfD, ctfN);
		String decryptedVoteString = rsa.correctDecrypt(encryptedVote, ctfD, ctfN);

		BigInteger decryptedValNo = new BigInteger(decryptedValNoString);
		BigInteger decryptedVote = new BigInteger(decryptedVoteString);

		System.out.println("\nReceived encrypted validation number " + encryptedValNo + " and encrypted vote " + encryptedVote);
		System.out.println("Valdiation number decrypted to " + decryptedValNo + " and vote decrypted to " + decryptedVote + "\n");

		BigInteger voteCheck = new BigInteger("0");

		if (voteRecord.containsKey(decryptedValNo)) {
			if (voteRecord.get(decryptedValNo).compareTo(new BigInteger("0")) == 0) {
				voteRecord.put(decryptedValNo, decryptedVote);
				voteCheck = new BigInteger("1");

				System.out.println("Vote has been counted.");

				try {
					claSocket = new Socket(serverName, claPort2);

					System.out.println("Sending Validation Number of user who voted to CLA.");

					ObjectOutputStream out = new ObjectOutputStream(claSocket.getOutputStream());

					String voterVotedRecord = decryptedValNo.toString() + ",1";
					String voterVotedRecordEncrypted = rsa.correctEncrypt(voterVotedRecord, claE, claN);

					out.writeObject(voterVotedRecordEncrypted);
					out.flush();

					claSocket.close();

				} catch (IOException e) {
					e.printStackTrace();
				}	

				if (!voteTally.containsKey(decryptedVote)) {
					voteTally.put(decryptedVote, 1);
				}
				else {
					voteTally.put(decryptedVote, voteTally.get(decryptedVote) + 1);;
				}

				writeVoteResults();
				writeWhoVoted();
			}
			else {
				voteCheck = new BigInteger("2");
				System.out.println("This person has already voted.");
			}
		}
		else {
			System.out.println("User's validation number is invalid.");
		}

		String voteCheckString = voteCheck.toString();

		String voteCheckStringEncrypted = rsa.correctEncrypt(voteCheckString, ctfD, ctfN);
		
		try {
			Thread.sleep(100);
			ObjectOutputStream out = new ObjectOutputStream(voter.getOutputStream());

			out.writeObject(voteCheckStringEncrypted);
			out.flush();

		} catch (IOException | InterruptedException e) {
			
			e.printStackTrace();
		}

	}



	public static void readVoteResults(String fileName) {
		String line = null;
		StringBuilder sb = new StringBuilder();

		try {
			FileReader fileReader = new FileReader(fileName);
			BufferedReader br = new BufferedReader(fileReader);

			while ((line = br.readLine()) != null) {
				String[] fileValues = line.split(",");

				String candidateNumber = fileValues[0].replaceFirst(".*?(\\d+).*", "$1");

				voteTally.put(BigInteger.valueOf(Integer.parseInt(candidateNumber)), Integer.parseInt(fileValues[1]));
			}
			br.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}



	public static void writeVoteResults() {
		String fileName = "VoteResults.txt";

		try {
			File file = new File(fileName);

			if (file.exists()) {
				file.delete();
			}

			file.createNewFile();

			FileWriter fw = new FileWriter(file, true);
			BufferedWriter bw = new BufferedWriter(fw);


			for (Entry<BigInteger, Integer> voteCount : voteTally.entrySet()) {
				String line = "Candidate " + voteCount.getKey().toString() + "," + voteCount.getValue();
				bw.write(line);
				bw.newLine();
			}

			bw.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
	}



	public static void readWhoVoted(String fileName) {
		String line = null;
		StringBuilder sb = new StringBuilder();

		try {
			FileReader fileReader = new FileReader(fileName);
			BufferedReader br = new BufferedReader(fileReader);

			while ((line = br.readLine()) != null) {
				String[] fileValues = line.split(",");

				voteRecord.put(new BigInteger(fileValues[0]), new BigInteger(fileValues[1]));
			}
			br.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}



	public void writeWhoVoted() {
		String fileName = "WhoVoted.txt";

		try {
			File file = new File(fileName);

			if (file.exists()) {
				file.delete();
			}

			file.createNewFile();

			FileWriter fw = new FileWriter(file, true);
			BufferedWriter bw = new BufferedWriter(fw);


			for (Entry<BigInteger, BigInteger> whoVoted : voteRecord.entrySet()) {
				String line = whoVoted.getKey().toString() + "," + whoVoted.getValue().toString();
				bw.write(line);
				bw.newLine();
			}

			bw.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
	}



	Boolean stop = false;

	public void listen() {
		(new Thread() {	
			@SuppressWarnings("unchecked")
			public void run() {
				try {
					claServersocket = new ServerSocket(claPort);
					Socket cla = null;
					while (true && !stop) {
						cla = claServersocket.accept();
						System.out.println("\nCLA has sent user validation numbers.");

						ObjectInputStream input = new ObjectInputStream(cla.getInputStream());
						
						List<String> encryptedVoterValNos = new ArrayList<>();
						encryptedVoterValNos = (List<String>) input.readObject();
						for (String encryptedValNo: encryptedVoterValNos) {
							String decryptedValNoString = rsa.correctDecrypt(encryptedValNo, ctfD, ctfN);
							BigInteger decryptedValNo = new BigInteger(decryptedValNoString);

							System.out.println("received encrypted validation number " + encryptedValNo);
							System.out.println("Decrypted to " + decryptedValNoString + "\n");

							if (!voteRecord.containsKey(decryptedValNo)) {
								voteRecord.put(decryptedValNo, new BigInteger("0"));
								writeWhoVoted();
							}
						}

						System.out.println("Validation numbers have been updated.");
						System.out.println("All Known validation numbers:");
						for (Entry<BigInteger, BigInteger> justVoterValNos : voteRecord.entrySet()) {
							System.out.println(justVoterValNos.getKey());
						}
						System.out.println();

						cla.close();
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
				try {
					claServersocket.close();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}).start();


		(new Thread() {
			@Override
			public void run() {

				try {
					voterServersocket = new ServerSocket(voterPort);
					System.out.println("Waiting for a user to vote." );
					while (true && !stop) {
						Socket voter = voterServersocket.accept();
						System.out.println("\nA Potential Voter has sent their vote.");
						String voterValNoAndVote;

						ObjectInputStream in = new ObjectInputStream(voter.getInputStream());

						voterValNoAndVote = (String) in.readObject();

						switch (voterValNoAndVote.substring(0, 1)) {					
							case "1":
								countVote(voterValNoAndVote, voter);
								break;
						}					
					}
					voterSocket.close();
				} catch (Exception e) {
					e.printStackTrace();
				}
				
				
			}

		}).start();	
	}

	public static void main(String[] args) {
		CTF ctf = new CTF();

		BigInteger claPu[] = ctf.readKeys("CLAPublic.txt");
		claE = claPu[0];
		claN = claPu[1];

		BigInteger ctfPu[] = ctf.readKeys("CTFPublic.txt");
		ctfE = ctfPu[0];

		BigInteger ctfPr[] = ctf.readKeys("CTFPrivate.txt");
		ctfD = ctfPr[0];
		ctfN = ctfPr[1];

		readVoteResults("VoteResults.txt");
		readWhoVoted("WhoVoted.txt");

		ctf.listen();		
	}
	
}