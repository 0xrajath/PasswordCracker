package main;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.io.*;
import java.util.*;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import java.util.Base64.Decoder;


public class PasswordCracker {

	public static void main(String[] args) {
		try {
				File passwordsFile = new File("resources/pswd.txt");
				FileInputStream passwordStream = new FileInputStream(passwordsFile);
				BufferedReader passwordBuffer = new BufferedReader(new InputStreamReader(passwordStream));
				
				Map<String, String> usernameToDecodedPassword = new HashMap<String, String>();
				Map<String, String> usernameToDecodedSalt = new HashMap<String, String>();
				
				
				//Parse the buffer to extract usernames and passwords
				String password_file_line = null;
				while ((password_file_line = passwordBuffer.readLine()) != null) {
					String[] splitLine = password_file_line.split("(\\s)*:(\\s)*");
					
					if(!splitLine[0].equals("username")) { //Not storing first line which is header
						//System.out.println(splitLine[0]+" - "+splitLine[1]+" - "+splitLine[2]+" - "+splitLine[3]);
						
						
						usernameToDecodedPassword.put(splitLine[0], splitLine[3]);
						usernameToDecodedSalt.put(splitLine[0], splitLine[1]);
					}
					
					
					
				/*
					//First case: password hashed with no salt
					if(splited.length == 3){
						non_salted_passwords.put(splited[0], splited[2]);
					}
					
					//Second case: password hashed with a salt
					else{
						salted_passwords.put(splited[0], splited[3]);
						salted_passwords_salts.put(splited[0], splited[2]);
					}
					*/
				}
			
				//Closing Buffer - Done reading password file
				passwordBuffer.close();
				
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
