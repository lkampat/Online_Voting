import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.TreeMap;

public class Voter {
	static RSA rsa = new RSA();
	static String serverName = "localhost";

	static String username, password;

	static BigInteger valNo;
	static HashMap<String, String> allValNos = new HashMap<String, String>();
	static String val1="";
	
	static BigInteger ctfE;
	static BigInteger ctfN;
	static int ctfPort = 6101;
	static Socket ctfSocket;

	static BigInteger claE;
	static BigInteger claN;
	static int claPort = 7101;
	static Socket claSocket;

	static BigInteger voterE = null;
	static BigInteger voterD = null;
	static BigInteger voterN = null;

	static Voter voter = new Voter();
	static String voterPu = null;
	static String valNoString;



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

	public BigInteger[] readOwnKeys(String fileName, String username) {
		BigInteger keyValues[] = new BigInteger[2];
		String line = null;
		StringBuilder sb = new StringBuilder();
		try {
			FileReader fileReader = new FileReader(fileName);
			BufferedReader br = new BufferedReader(fileReader);

			while ((line = br.readLine()) != null) {
				String[] fileKeys = line.split(",");

				if (fileKeys[0].equals(username)) {
					keyValues[0] = new BigInteger(fileKeys[1]);
					keyValues[1] = new BigInteger(fileKeys[2]);
				}
			}
			br.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return keyValues;
	}	



	public void closeSocket(Socket socketToClose) {
		try {
			socketToClose.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}



	public Boolean authorization(String username, String password) {
		String authorizationCheck = null;
		Boolean isAuthorized2 = false;

		try {
			claSocket = new Socket(serverName, claPort);

			System.out.println("\nChecking authorization with CLA.");

			ObjectOutputStream out = new ObjectOutputStream(claSocket.getOutputStream());
			
			String usernameEncrypted = "";
			String passwordEncrypted = "";
			usernameEncrypted = rsa.correctEncrypt(username, claE, claN);
			passwordEncrypted = rsa.correctEncrypt(password, claE, claN);

			String combinedEncrypted = "0," + usernameEncrypted + "," + passwordEncrypted;

			System.out.println("Sending username " + username + " and password " + password + " encrypted as");
			System.out.println(combinedEncrypted);

			out.writeObject(combinedEncrypted);
			out.flush();
			

			ObjectInputStream in = new ObjectInputStream(claSocket.getInputStream());

			authorizationCheck = (String) in.readObject();
			String[] splitValNo = authorizationCheck.split(",");

			System.out.println("\nValidation number received encrypted as " + splitValNo[1]);

			valNoString = rsa.correctDecrypt(splitValNo[1], voterD, voterN);

			System.out.println("Decrypted to " + valNoString);

			switch (splitValNo[0]) {
				case "1":
					isAuthorized2 = true;
					System.out.println("\nYou have already been assigned a validation number!");
					System.out.println("Your validation number: " + valNoString + "\n");
					break;
				case "2":
					isAuthorized2 = true;
					System.out.println("\nHere is your validation number: " + valNoString + "\n");
					break;
			}

		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}

		closeSocket(claSocket);
		return isAuthorized2;
	}



	public int castVote(String valNoAndVote) {
		String[] valNoAndVoteSplit = valNoAndVote.split(",");

		int voteStatus = 0;		

		try {
			System.out.println("\nSending vote to CTF.");
			ctfSocket = new Socket(serverName, ctfPort);
			
			String valNoEncrypted = rsa.correctEncrypt(valNoAndVoteSplit[0], ctfE, ctfN);
			String voteEncrypted = rsa.correctEncrypt(valNoAndVoteSplit[1], ctfE, ctfN);
			String fullEncryptedString = "1," + valNoEncrypted +"," + voteEncrypted;

			System.out.println("Sending validation number encrypted as " + valNoEncrypted + " and vote encrypted as " + voteEncrypted);

			ObjectOutputStream out = new ObjectOutputStream(ctfSocket.getOutputStream());
			out.writeObject(fullEncryptedString);
			out.flush();

			ObjectInputStream in = new ObjectInputStream(ctfSocket.getInputStream());
			String voteStatusStringEncrypted = (String) in.readObject();

			String voteStatusStringDecrypted = rsa.correctDecrypt(voteStatusStringEncrypted, ctfE, ctfN);
			voteStatus = Integer.parseInt(voteStatusStringDecrypted);
			
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}
		
		closeSocket(ctfSocket);

		return voteStatus;
	}



	@SuppressWarnings("resource")
	public static void main(String[] args) throws Exception {
		
		BigInteger claPu[] = voter.readKeys("CLAPublic.txt");
		claE = claPu[0];
		claN = claPu[1];

		BigInteger ctfPu[] = voter.readKeys("CTFPublic.txt");
		ctfE = ctfPu[0];
		ctfN = ctfPu[1];

		// storeValidationNos();
		System.out.println("\nPlease log in to the election system.");
		Scanner scanner = new Scanner(System.in);
		
		String option;

		Boolean isAuthorized = false;

		while (!isAuthorized) {
			do {
				System.out.println("Username:");
				username = scanner.next();
				System.out.println("Password:");
				password = scanner.next();

				BigInteger ownPu[] = voter.readOwnKeys("VoterPublic.txt", username);
				voterE = ownPu[0];
				voterN = ownPu[1];
				voterPu = ownPu[0] + "," + ownPu[1];

				BigInteger ownPr[] = voter.readOwnKeys("VoterPrivate.txt", username);
				voterD = ownPr[0];

				if (voterE == null || voterD == null) {
					System.out.println("Invalid Username.");
				}
			} while(voterE == null || voterD == null);

			voter = new Voter();
			
			isAuthorized = voter.authorization(username, password);

			if (!isAuthorized) {
				System.out.println("CLA: Invalid login.");
			}
		}

		System.out.println("What would you like to do?\n");

		String choice;
		do {

	        System.out.println( "Menu:" );
	        System.out.println( "1. Cast Vote" );
	        System.out.println( "2. Exit" );
			
			choice = scanner.next();

			switch (choice) {
				case "1": {
					// voter.displayCandidateList();
					System.out.println("\nEnter your Validation Number:");
					String myValNo = scanner.next();

					System.out.println("\n1: Candidate 1");
					System.out.println("2: Candidate 2");
					System.out.println("3: Candidate 3");
					System.out.println("\nWhich candidate do you want to vote for?");
					String myVote = scanner.next();

					String myValNoAndVote = myValNo + "," + myVote;

					int voteStatus = voter.castVote(myValNoAndVote);

					switch (voteStatus) {
						case 0:
							System.out.println("CTF: Your validation number is invalid.");
							break;
						case 1:
							System.out.println("CTF: Your vote has been counted.");
							break;
						case 2:
							System.out.println("CTF: You have already voted.");
							break;
					}
					System.out.println();

					break;
				}
				case "2": {
					System.out.println("\nGoodbye!");
					break;
				}
				default: {
					System.out.println("Invalid input.");
					break;
				}
			}
		} while (!choice.equals("2"));
	}
}