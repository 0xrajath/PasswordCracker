/*
* Name: Rajath George Alex
* Description: Password Cracking Program
*/

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
	
	//Lists of Resources for Hybrid attack
	private static List<String> numbersAtEnd = new ArrayList<String>(); //Numbers At End
	private static List<String> dob = new ArrayList<String>(); //Date of Birth
	private static List<String> specialSymbols = new ArrayList<String>(); //Date of Birth
	
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
				//Populating Resource Lists from Resource Files
				populateResourceList(numbersAtEnd, "resources/hybridattack/numbersAtEnd.txt");	
				populateResourceList(dob, "resources/hybridattack/dob.txt");
				populateResourceList(specialSymbols, "resources/hybridattack/specialSymbols.txt");
				
//				for(String s: specialSymbols) {
//					System.out.println(s);
//				}
			
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
					System.out.println("Starting Step 1a");
					//Step 1a: Checking with username as plaintextpassword directly
					checkHackCombinations(pFileLine.getUsername(), pFileLine.getUsername(), pFileLine.getSalt(), pFileLine.getHashedPassword());
					System.out.println("Finished Step 1a");
					
					System.out.println("Starting Step 1b");
					//Step 1b: Checking with just surname in username as plaintextpassword
					checkHackCombinations(pFileLine.getUsername().substring(1), pFileLine.getUsername(), pFileLine.getSalt(), pFileLine.getHashedPassword());
					System.out.println("Finished Step 1b");
				}
							
				
				
				//Input Dictionary1				
				BufferedReader dictionaryBuffer1 = fileToBuffer("resources/dictionaryattack/john.txt");				
				//Step 2: Dictionary Attack
				System.out.println("Starting Step 2");
				String dictionaryFileLine = null;
//				int count = 1;
				while ((dictionaryFileLine = dictionaryBuffer1.readLine()) != null) {	
//					System.out.println(count);
//					count++;
					for(String salt: saltList) {//Checking all available salts
						//Step 2a: Checking dictionary directly
						checkHack(dictionaryFileLine.trim(), saltToUsername.get(salt), salt, saltToPassword.get(salt));
						
						//Step 2b: Dictionary with numbers at end
						for(String number: numbersAtEnd) {
							checkHack(dictionaryFileLine.trim()+number, saltToUsername.get(salt), salt, saltToPassword.get(salt));
						}
						
						//Step 2c: Dictionary with dob at end
						for(String dateOfBirth: dob) {
							checkHack(dictionaryFileLine.trim()+dateOfBirth, saltToUsername.get(salt), salt, saltToPassword.get(salt));
						}
						
						//Step 2d: Dictionary with symbols at end
						for(String symbol: specialSymbols) {
							checkHack(dictionaryFileLine.trim()+symbol, saltToUsername.get(salt), salt, saltToPassword.get(salt));
						}
						
						//Step 2e: Dictionary reversed
						String reversedDictionaryWord = new StringBuilder(dictionaryFileLine.trim().toLowerCase()).reverse().toString();
						checkHack(reversedDictionaryWord, saltToUsername.get(salt), salt, saltToPassword.get(salt));
						
						//Step 2f: First letter of Dictionary opposite case
						if(!dictionaryFileLine.trim().isEmpty()) {
							checkHack(makeFirstLetterOppositeCase(dictionaryFileLine.trim()), saltToUsername.get(salt), salt, saltToPassword.get(salt));
						}
						
						
//						//Checking Dictionary words and its combinations
//						checkHackCombinations(dictionaryFileLine.trim(), saltToUsername.get(salt), salt, saltToPassword.get(salt));
					}										
				}
				System.out.println("Finished Step 2");
				//Closing Buffer - Done reading dictionary file
				dictionaryBuffer1.close();
				
				
				
				//Printing out Username::Password matched pairs
				for (Map.Entry<String, String> entry : usernameToPlaintextPassword.entrySet()) {
				    System.out.println(entry.getKey()+"::"+entry.getValue());
				}					
				
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	
	
	//Method to check most occurring combinations of PlaintextPassword
	private static void checkHackCombinations(String plaintextPassword, String username, String encodedSalt , String encodedHashedPassword) {
		//Checking plaintextpassword directly
		checkHackSymbolNumberDOBCombinations(plaintextPassword, username, encodedSalt, encodedHashedPassword);
		
		//Checking plaintextpassword with first letter made to opposite case
		checkHackSymbolNumberDOBCombinations(makeFirstLetterOppositeCase(plaintextPassword), username, encodedSalt, encodedHashedPassword);
		
		//Checking plaintextpassword with all vowels removed
		String plaintextPasswordWOVowels = plaintextPassword.replaceAll("[AEIOUaeiou]", "");
		checkHackSymbolNumberDOBCombinations(plaintextPasswordWOVowels, username, encodedSalt, encodedHashedPassword);
		
		//Making plaintextpassword all lowercase and reversing it and then checking
		String reversedPlaintextPassword = new StringBuilder(plaintextPassword.toLowerCase()).reverse().toString();
		checkHackSymbolNumberDOBCombinations(reversedPlaintextPassword, username, encodedSalt, encodedHashedPassword);
		
		//Checking reversed Plaintextpassword with first letter made to opposite case
		checkHackSymbolNumberDOBCombinations(makeFirstLetterOppositeCase(reversedPlaintextPassword), username, encodedSalt, encodedHashedPassword);
		
		//Checking reversed Plaintextpassword with all vowels removed
		String reversedPlaintextPasswordWOVowels = reversedPlaintextPassword.replaceAll("[AEIOUaeiou]", "");
		checkHackSymbolNumberDOBCombinations(reversedPlaintextPasswordWOVowels, username, encodedSalt, encodedHashedPassword);		
	}
	
	
	//Method to make first letter of String opposite case
	private static String makeFirstLetterOppositeCase (String s) {
		if(Character.isLowerCase(s.charAt(0)))
			return s.substring(0, 1).toUpperCase() + s.substring(1);
		else
			return s.substring(0, 1).toLowerCase() + s.substring(1);
	}
	
	
	//Method to check Symbol and Dob combinations with given plaintextPassword
	private static void checkHackSymbolNumberDOBCombinations(String plaintextPassword, String username, String encodedSalt , String encodedHashedPassword) {
		//Step 1: Check with plaintextpassword directly
		checkHack(plaintextPassword, username, encodedSalt, encodedHashedPassword);
		
		//Step 2: Check with all combinations of plaintextpassword&dob and plaintextpassword&dob&symbol
		for(String dateOfBirth: dob) {
			checkHack(plaintextPassword+dateOfBirth, username, encodedSalt, encodedHashedPassword);
			checkHack(dateOfBirth+plaintextPassword, username, encodedSalt, encodedHashedPassword);
			for(String symbol: specialSymbols) {
				checkHack(plaintextPassword+dateOfBirth+symbol, username, encodedSalt, encodedHashedPassword);
				checkHack(dateOfBirth+symbol+plaintextPassword, username, encodedSalt, encodedHashedPassword);
				checkHack(plaintextPassword+symbol+dateOfBirth, username, encodedSalt, encodedHashedPassword);
				checkHack(symbol+dateOfBirth+plaintextPassword, username, encodedSalt, encodedHashedPassword);
				checkHack(symbol+plaintextPassword+dateOfBirth, username, encodedSalt, encodedHashedPassword);
				checkHack(dateOfBirth+plaintextPassword+symbol, username, encodedSalt, encodedHashedPassword);
			}
		}
		
		//Step 3: Check with all combinations of plaintextpassword&number and plaintextpassword&number&symbol 
		for(String number: numbersAtEnd) {
			checkHack(plaintextPassword+number, username, encodedSalt, encodedHashedPassword);
			checkHack(number+plaintextPassword, username, encodedSalt, encodedHashedPassword);
			for(String symbol: specialSymbols) {
				checkHack(plaintextPassword+number+symbol, username, encodedSalt, encodedHashedPassword);
				checkHack(number+symbol+plaintextPassword, username, encodedSalt, encodedHashedPassword);
				checkHack(plaintextPassword+symbol+number, username, encodedSalt, encodedHashedPassword);
				checkHack(symbol+number+plaintextPassword, username, encodedSalt, encodedHashedPassword);
				checkHack(symbol+plaintextPassword+number, username, encodedSalt, encodedHashedPassword);
				checkHack(number+plaintextPassword+symbol, username, encodedSalt, encodedHashedPassword);
			}
		}
		
		//Step 4: Check with all combinations of plaintextpassword&symbol 
		for(String symbol: specialSymbols) {
			checkHack(plaintextPassword+symbol, username, encodedSalt, encodedHashedPassword);
			checkHack(symbol+plaintextPassword, username,encodedSalt, encodedHashedPassword);
		}				
	}
	
	
	//Method to compare hashed plaintextpassword against available hashed password
	private static void checkHack(String plaintextPassword, String username, String encodedSalt , String encodedHashedPassword) {
		char [] plaintextPword = plaintextPassword.toCharArray();
		
		byte[] computedHashedPwd = hashPassword(plaintextPword,Base64.getDecoder().decode(encodedSalt),1,256);//Computing Hashed Password from Dictionary					
		if(Base64.getEncoder().encodeToString(computedHashedPwd).equals(encodedHashedPassword))
			usernameToPlaintextPassword.put(username, plaintextPassword);//Making an entry if match found	
	}
	
	
	//Hashing Algorithm used
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
	
	
	//File to BufferedReader Method
	private static BufferedReader fileToBuffer(String filePath) throws IOException {
		File file = new File(filePath);
		FileInputStream fileInputStream = new FileInputStream(file);
		BufferedReader buffer = new BufferedReader(new InputStreamReader(fileInputStream));
		return buffer;	
	}
	
	
	//Method to populate Resource Lists
	private static void populateResourceList(List<String> resourceList, String filePath) throws IOException {
		BufferedReader resourceListBuffer = fileToBuffer(filePath);		
		//Parse the buffer to extract String
		String fileLine = null;
		while ((fileLine = resourceListBuffer.readLine()) != null) {
			resourceList.add(fileLine.trim());
		}			
		//Closing Buffer - Done reading file
		resourceListBuffer.close();
	}
	
	

}
