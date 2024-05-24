import java.io.IOException;
import java.util.Map;
import java.nio.file.FileAlreadyExistsException;

/**
 * A class to store passwords. Passwords can be written to a file in an encrypted manner. A master
 * password is required to open each vault.
 * @author Hudson Hadley
 */
public class Vault {
    /**
     * The name of the vault
     */
    private String name;

    /**
     * The master password for this vault
     */
    private String masterPassword;

    /**
     * A map of names to passwords. An example of this could be "Netflix" --> (username, password)
     */
    private Map<String, Password> passwords;

    /**
     * Constructs an empty vault, initializing the member variables
     */
    public Vault() {

    }

    /**
     * Constructs a new vault with a certain name and master password
     * @param name the name we want to ascribe
     * @param masterPassword the master password we want to ascribe
     */
    public Vault(String name, String masterPassword) {

    }

    /**
     * Reads an encrypted file and sets the member variables as defined in the file.
     * @param fileName the name of the file we want to read
     * @throws IOException if the file is not found or if the file is formatted incorrectly
     */
    public void readFile(String fileName) throws IOException {

    }

    /**
     * Writes a vault to a file with the filename being the name of the vault
     * @throws NoSuchFieldException if the name of the Vault hasn't been set
     * @throws FileAlreadyExistsException if there already exists a file with the filename
     */
    public void writeToFile() throws NoSuchFieldException, FileAlreadyExistsException {

    }

    /**
     * Encrypts the current vault
     * @return an encrypted String representing the vault
     */
    private String encrypt() {
        return "";
    }

    /**
     * @return an unencrypted representation of the vault
     */
    @Override
    public String toString() {
        return "";
    }

    /**
     * @return the master password
     */
    public String getMasterPassword() {
        return "";
    }

    /**
     * Sets the master password
     */
    public void setMasterPassword() {

    }

    /**
     * Adds a password to the vault
     * @param name the name of the password we want to add
     * @param password the password we want to add
     */
    public void addPassword(String name, Password password) {

    }

    /**
     * Adds a password to the vault
     * @param name the name of the password we want to add
     * @param username the username we want to add
     * @param password the password we want to add
     */
    public void addPassword(String name, String username, String password) {

    }

    /**
     * Removes a password from the vault
     * @param name the name of the password we want to delete
     */
    public void deletePassword(String name) {

    }

    /**
     * Sets the username of a record in the vault to be what we have inputted
     * @param name the name of the record we want to change
     * @param username the username we want to set
     */
    public void setUsername(String name, String username) {

    }

    /**
     * Sets the password of a record in the vault to be what we have inputted
     * @param name the name of the record we want to change
     * @param password the password we want to set
     */
    public void setPassword(String name, String password) {

    }
}