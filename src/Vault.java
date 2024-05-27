import java.io.*;
import java.util.Map;
import java.util.HashMap;
import java.util.Scanner;

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
        name = "";
        masterPassword = "";
        passwords = new HashMap<>();
    }

    /**
     * Constructs a new vault with a certain name and master password
     * @param name the name we want to ascribe
     * @param masterPassword the master password we want to ascribe
     */
    public Vault(String name, String masterPassword) {
        this.name = name;
        this.masterPassword = masterPassword;
        passwords = new HashMap<>();
    }

    /**
     * Reads an encrypted file and sets the member variables as defined in the file.
     * @throws IOException if the file is not found or if the file is formatted incorrectly
     */
    public void readFile() throws IOException {
        File file = new File(name);
        FileInputStream inputStream = new FileInputStream(file);
        byte[] fileBytes = inputStream.readAllBytes();

        String decryptedString = AES.decrypt(fileBytes, masterPassword);
        Scanner stringScanner = new Scanner(decryptedString);

        Scanner lineScanner;
        while (stringScanner.hasNext()) {
            lineScanner = new Scanner(stringScanner.nextLine());
            lineScanner.useDelimiter(", ");

            String name = lineScanner.next();
            String username = lineScanner.next();
            String password = lineScanner.next();

            addPassword(name, username, password);

            lineScanner.close();
        }
    }

    /**
     * Writes a vault to a file with the filename being the name of the vault
     * @throws NoSuchFieldException if the name of the Vault hasn't been set
     * @throws IOException if we are unable to write to a file with the name of the vault
     */
    public void writeToFile() throws NoSuchFieldException, IOException {
        if (name.isEmpty()) // name == ""
            throw new NoSuchFieldException("Name has not been set. Unable to name file");

        byte[] encryptedBytes = AES.encrypt(this.toString(), masterPassword);

        FileOutputStream outFile = new FileOutputStream(name);
        outFile.write(encryptedBytes);
        outFile.close();
    }

    /**
     * @return an unencrypted representation of the vault
     */
    @Override
    public String toString() {
        StringBuilder vaultBuilder = new StringBuilder();

        for (String record: passwords.keySet()) {
            Password recordPassword = passwords.get(record);

            vaultBuilder.append(String.format("%s, %s, %s\n",
                    record, recordPassword.getUsername(), recordPassword.getPassword()));
        }

        return vaultBuilder.toString();
    }

    /**
     * @return the master password
     */
    public String getMasterPassword() {
        return masterPassword;
    }

    /**
     * Sets the master password
     * @param masterPassword the master password we want to set
     */
    public void setMasterPassword(String masterPassword) {
        this.masterPassword = masterPassword;
    }

    /**
     * Adds a password to the vault
     * @param name the name of the password we want to add
     * @param password the password we want to add
     */
    public void addPassword(String name, Password password) {
        passwords.put(name, new Password(password));
    }

    /**
     * Adds a password to the vault
     * @param name the name of the password we want to add
     * @param username the username we want to add
     * @param password the password we want to add
     */
    public void addPassword(String name, String username, String password) {
        passwords.put(name, new Password(username, password));
    }

    /**
     * Removes a password from the vault
     * @param name the name of the password we want to delete
     */
    public void deletePassword(String name) {
        passwords.remove(name);
    }

    /**
     * Sets the username of a record in the vault to be what we have inputted
     * @param name the name of the record we want to change
     * @param username the username we want to set
     */
    public void setUsername(String name, String username) {
        passwords.get(name).setUsername(username);
    }

    /**
     * Sets the password of a record in the vault to be what we have inputted
     * @param name the name of the record we want to change
     * @param password the password we want to set
     */
    public void setPassword(String name, String password) {
        passwords.get(name).setPassword(password);
    }
}