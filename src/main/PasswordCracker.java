package main;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.io.*;
import java.util.*;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;



public class PasswordCracker {

	public static void main(String[] args) {
		try {
				
				List<String> saltList = new ArrayList<String>();
				Map<String, String> saltToPassword = new HashMap<String, String>();
				Map<String, String> saltToUsername = new HashMap<String, String>();
				Map<String, String> usernameToPlaintextPassword = new HashMap<String, String>();
				
				//Input Password File
				File passwordsFile = new File("resources/pswd.txt");
				FileInputStream passwordStream = new FileInputStream(passwordsFile);
				BufferedReader passwordBuffer = new BufferedReader(new InputStreamReader(passwordStream));
		
				//Parse the buffer to extract usernames and passwords
				String passwordFileLine = null;
				while ((passwordFileLine = passwordBuffer.readLine()) != null) {
					String[] splitLine = passwordFileLine.split("(\\s)*:(\\s)*");
					
					if(!splitLine[0].equals("username")) { //Not storing first line which is header
						//System.out.println(splitLine[0]+" - "+splitLine[1]+" - "+splitLine[2]+" - "+splitLine[3]);
						
						saltList.add(splitLine[1]);
						saltToPassword.put(splitLine[1], splitLine[3]);
						saltToUsername.put(splitLine[1], splitLine[0]);
					}
				}
			
				//Closing Buffer - Done reading password file
				passwordBuffer.close();
				
				
				//Input Dictionary1
				File dictionaryFile1 = new File("resources/john.txt");
				FileInputStream dictionaryStream1 = new FileInputStream(dictionaryFile1);
				BufferedReader dictionaryBuffer1 = new BufferedReader(new InputStreamReader(dictionaryStream1));
				
				String dictionaryFileLine = null;
				while ((dictionaryFileLine = dictionaryBuffer1.readLine()) != null) {
					char [] plaintextPassword = dictionaryFileLine.trim().toCharArray();
										
					for(String salt: saltList) {//Checking all available salts
						byte[] computedHashedPwd = hashPassword(plaintextPassword,Base64.getDecoder().decode(salt),1,256);//Computing Hashed Password from Dictionary					
						if(Base64.getEncoder().encodeToString(computedHashedPwd).equals(saltToPassword.get(salt)))
							usernameToPlaintextPassword.put(saltToUsername.get(salt), dictionaryFileLine.trim());//Making an entry if match found					
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
	
	public static byte[] hashPassword( final char[] password, final byte[] salt, final int iterations, final int keyLength ) {
		 
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
