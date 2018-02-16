/*
* Name: Rajath George Alex
* Description: Program to crack encrypted password files using Dictionary+Hybrid attack
*/

package beans;

public class PasswordFileLine {
	String username;
	String salt;
	String hashedPassword;
	
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getSalt() {
		return salt;
	}
	public void setSalt(String salt) {
		this.salt = salt;
	}
	public String getHashedPassword() {
		return hashedPassword;
	}
	public void setHashedPassword(String hashedPassword) {
		this.hashedPassword = hashedPassword;
	}
	
}
