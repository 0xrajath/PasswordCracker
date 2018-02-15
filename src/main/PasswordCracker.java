package main;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.io.*;
import java.util.*;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import beans.*;


public class PasswordCracker {
	
	//Data Structure for Hybrid attacks
	private static List<PasswordFileLine> passwordFileLineList = new ArrayList<PasswordFileLine>();
	
	//Data Structures for faster access for Dictionary use
	private static List<String> saltList = new ArrayList<String>();
	private static Map<String, String> saltToPassword = new HashMap<String, String>();
	private static Map<String, String> saltToUsername = new HashMap<String, String>();
	
	//Final Data Structures for Cracked Username-Password combinations
	private static Map<String, String> usernameToPlaintextPassword = new HashMap<String, String>();
	
	public static void main(String[] args) {
		try {				
							
				//Input Password File				
				BufferedReader passwordBuffer = fileToBuffer("resources/pswd.txt");		
				//Parse the buffer to extract usernames and passwords
				String passwordFileLine = null;
				while ((passwordFileLine = passwordBuffer.readLine()) != null) {
					String[] splitLine = passwordFileLine.split("(\\s)*:(\\s)*");
					
					if(!splitLine[0].equals("username")) { //Not storing first line which is header
						//System.out.println(splitLine[0]+" - "+splitLine[1]+" - "+splitLine[2]+" - "+splitLine[3]);
						PasswordFileLine pFileLine = new PasswordFileLine();
						pFileLine.setUsername(splitLine[0]);
						pFileLine.setSalt(splitLine[1]);
						pFileLine.setHashedPassword(splitLine[3]);
						
						passwordFileLineList.add(pFileLine);//List of Password File Lines
						
						saltList.add(splitLine[1]);
						saltToPassword.put(splitLine[1], splitLine[3]);
						saltToUsername.put(splitLine[1], splitLine[0]);
					}
				}			
				//Closing Buffer - Done reading password file
				passwordBuffer.close();
				
				
				
				//Step 1: Check with usernames and its combinations as Passwords
				for(PasswordFileLine pFileLine: passwordFileLineList) {					
					//Step 1a: Check with username directly as password
					checkHack(pFileLine.getUsername(), pFileLine.getUsername(), pFileLine.getSalt(), pFileLine.getHashedPassword());					
					//Step 1b: Check with username reversed as password
					String reversedUsername = new StringBuilder(pFileLine.getUsername()).reverse().toString();		
				}
				
				
				
				//Input Dictionary1				
				BufferedReader dictionaryBuffer1 = fileToBuffer("resources/john.txt");				
				//Step 2: Dictionary Attack
				String dictionaryFileLine = null;
				while ((dictionaryFileLine = dictionaryBuffer1.readLine()) != null) {										
					for(String salt: saltList) {//Checking all available salts
						checkHack(dictionaryFileLine.trim(), saltToUsername.get(salt), salt, saltToPassword.get(salt));
					}										
				}			
				//Closing Buffer - Done reading dictionary file
				dictionaryBuffer1.close();
				
				
				
				//Printing out Username::Password matched pairs
				for (Map.Entry<String, String> entry : usernameToPlaintextPassword.entrySet()) {
				    System.out.println(entry.getKey()+"::"+entry.getValue());
				}					
				
				
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	
	private static void checkHack(String plaintextPassword, String username, String encodedSalt , String encodedHashedPassword) {
		char [] plaintextPword = plaintextPassword.toCharArray();
		
		byte[] computedHashedPwd = hashPassword(plaintextPword,Base64.getDecoder().decode(encodedSalt),1,256);//Computing Hashed Password from Dictionary					
		if(Base64.getEncoder().encodeToString(computedHashedPwd).equals(encodedHashedPassword))
			usernameToPlaintextPassword.put(username, plaintextPassword);//Making an entry if match found	
	}
	
	
	private static BufferedReader fileToBuffer(String filePath) throws FileNotFoundException {
		File file = new File(filePath);
		FileInputStream fileInputStream = new FileInputStream(file);
		BufferedReader buffer = new BufferedReader(new InputStreamReader(fileInputStream));
		return buffer;	
	}
	
	private static byte[] hashPassword( final char[] password, final byte[] salt, final int iterations, final int keyLength ) {
		 
	       try {
	           SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
	           PBEKeySpec spec = new PBEKeySpec( password, salt, iterations, keyLength );
	           SecretKey key = skf.generateSecret( spec );
	           byte[] res = key.getEncoded( );
	           return res;
	 
	       } catch( NoSuchAlgorithmException | InvalidKeySpecException e ) {
	           throw new RuntimeException( e );
	       }
	}
	
	

}
