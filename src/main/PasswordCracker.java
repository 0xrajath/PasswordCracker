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
				
				List<byte[]> decodedSalt = new ArrayList<byte[]>();
				Map<byte[], byte[]> decodedSaltToDecodedPassword = new HashMap<byte[], byte[]>();
				Map<byte[], String> decodedSaltToUsername = new HashMap<byte[], String>();
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
						
						decodedSalt.add(Base64.getDecoder().decode(splitLine[1]));//Decoding Base64 Salt and adding to List
						decodedSaltToDecodedPassword.put(Base64.getDecoder().decode(splitLine[1]), Base64.getDecoder().decode(splitLine[3]));
						//System.out.println(Base64.getDecoder().decode(splitLine[3]));
						decodedSaltToUsername.put(Base64.getDecoder().decode(splitLine[1]), splitLine[0]);
					}
				}
			
				//Closing Buffer - Done reading password file
				passwordBuffer.close();
				
//				for(byte[] salt: decodedSalt) {
//					System.out.println(salt.toString());
//				}
				
				String test = Base64.getEncoder().encodeToString(decodedSaltToDecodedPassword.get(Base64.getDecoder().decode("B9OGLTbJNATU+ZJdnaUUGnMe4hOeK9qRW/6zG+Lkn0E=")));
				System.out.println(test);
				
				//Input Dictionary1
				File dictionaryFile1 = new File("resources/test.txt");
				FileInputStream dictionaryStream1 = new FileInputStream(dictionaryFile1);
				BufferedReader dictionaryBuffer1 = new BufferedReader(new InputStreamReader(dictionaryStream1));
				
				String dictionaryFileLine = null;
				while ((dictionaryFileLine = dictionaryBuffer1.readLine()) != null) {
					char [] plaintextPassword = dictionaryFileLine.trim().toCharArray();
					//System.out.println(plaintextPassword);
										
					for(byte[] salt: decodedSalt) {//Checking all available salts
						byte[] computedHashedPwd = hashPassword(plaintextPassword,salt,1,256);//Computing Hashed Password from Dictionary					
						//System.out.println(computedHashedPwd);
						if(Arrays.equals(computedHashedPwd, decodedSaltToDecodedPassword.get(salt)))
							usernameToPlaintextPassword.put(decodedSaltToUsername.get(salt), dictionaryFileLine.trim());//Making an entry if match found
								
					}	
					
					//System.out.println(plaintextPassword);					
				}
			
				//Closing Buffer - Done reading dictionary file
				dictionaryBuffer1.close();
				
				//System.out.println("Hello");
				//Printing out Username::Password matched pairs
				for (Map.Entry<String, String> entry : usernameToPlaintextPassword.entrySet()) {
				    System.out.println(entry.getKey()+"::"+entry.getValue());
				}	
				//System.out.println("Hello again");
				
//				String hp = "cTrpsypRsEoi0Sotz1r0jvkTjTSfA60yxO3RzBRNF3o=";
//				byte[] hpwd = Base64.getDecoder().decode(hp);
//				String s = "B9OGLTbJNATU+ZJdnaUUGnMe4hOeK9qRW/6zG+Lkn0E=";
//				byte[] slt = Base64.getDecoder().decode(s);
//				char [] p = "computer".toCharArray();
//				
//				System.out.println(Base64.getEncoder().encodeToString(hashPassword(p, slt,1, 256)));
//				
//				if(Base64.getEncoder().encodeToString(hashPassword(p, slt,1, 256)).equals(hp))
//					System.out.println(true);
//				else
//					System.out.println(false);
//				
//				if(Arrays.equals(hashPassword(p, slt,1, 256), hpwd))
//					System.out.println(true);
//				else
//					System.out.println(false);
				
				
				
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
