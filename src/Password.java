/**
 * This class holds a username password pair.
 * @author Hudson Hadley
 */
public class Password {
    /**
     * A String of a username
     */
    private String username;
    /**
     * A String of a password
     */
    private String password;

    /**
     * Constructs a Password with a username and password
     * @param username a String representation of a username
     * @param password a String represent of a password
     */
    public Password(String username, String password) {
        this.username = username;
        this.password = password;
    }

    /**
     * A copy constructor that makes a new Password with the same username and password
     * @param other a Password object we want to copy
     */
    public Password(Password other) {
        this.username = other.username;
        this.password = other.password;
    }

    /**
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * @return the password
     */
    public String getPassword() {
        return password;
    }

    /**
     * Sets the username to what is inputted
     * @param username the username we want to set
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Sets the password to what is inputted
     * @param password the password we want to set
     */
    public void setPassword(String password) {
        this.password = password;
    }
}
