import java.io.*;
import java.util.*;

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

    private String vaultDirectory;
    
    /**
     * Constructs an empty vault, with a given filename. The vault name will be the name of the file.
     * Note that the file should have a .pmv extension
     * @param name the name we want to give to a new vault
     * @throws IllegalArgumentException if the file does not end in .pmv
     */
    public Vault(String filename) throws IllegalArgumentException {
        filename = filename.replace("\\", "/");
        String[] path = filename.split("/");

        String regex = ".*\\.pmv";
        if (!path[path.length - 1].matches(regex)) {
            throw new IllegalArgumentException("Vaults must have .pmv extensions");
        }

        // Get everything upto the filename

        StringBuilder vaultDirectoryBuilder = new StringBuilder();
        for (int i = 0; i < path.length - 1; i++) {
            vaultDirectoryBuilder.append(path[i]);
            vaultDirectoryBuilder.append("/");
        }

        vaultDirectory = vaultDirectoryBuilder.toString();
        this.name = path[path.length - 1].substring(0, path[path.length - 1].length() - 4);
        masterPassword = "";
        passwords = new TreeMap<>();
    }

    /**
     * Constructs a new vault with a certain path/name and master password
     * @param filename the path of the new vault
     * @param masterPassword the master password we want to ascribe
     */
    public Vault(String filename, String masterPassword) {
        filename = filename.replace("\\", "/");
        String[] path = filename.split("/");

        String regex = ".*\\.pmv";
        if (!path[path.length - 1].matches(regex)) {
            throw new IllegalArgumentException("Vaults must have .pmv extensions");
        }

        // Get everything upto the filename

        StringBuilder vaultDirectoryBuilder = new StringBuilder();
        for (int i = 0; i < path.length - 1; i++) {
            vaultDirectoryBuilder.append(path[i]);
            vaultDirectoryBuilder.append("/");
        }

        vaultDirectory = vaultDirectoryBuilder.toString();
        this.name = path[path.length - 1].substring(0, path[path.length - 1].length() - 4);
        this.masterPassword = masterPassword;
        passwords = new HashMap<>();
    }

    /**
     * Validates a password by seeing if it correctly decrypts the corresponding file.
     * @param masterPassword the password we want to use to decrypt
     * @throws IllegalStateException if the password has already been set
     */
    public boolean validatePassword(String masterPassword) {
        if (!this.masterPassword.isEmpty())
            throw new IllegalStateException("Password is already set");

        this.masterPassword = masterPassword;

        try {
            readFile();
            return true;
        } catch (Exception e) {
            this.masterPassword = "";
            return false;
        }
    }

    /**
     * Reads an encrypted file and sets the member variables as defined in the file.
     * @throws IOException if the file is not found
     * @throws NoSuchElementException if the file is not properly formatted
     */
    public void readFile() throws IOException, NoSuchElementException {
        File file = new File(vaultDirectory + name + ".pmv");
        FileInputStream inputStream = new FileInputStream(file);
        byte[] fileBytes = inputStream.readAllBytes();

        String decryptedString;
        // If we fail to decrypt the file, it will be unable to decrypt due to the key being wrong
        try {
            decryptedString = AES.decrypt(fileBytes, masterPassword);
        } catch (IllegalArgumentException iae) {
            inputStream.close();
            throw new IOException("File not formatted properly");
        }

        Scanner stringScanner = new Scanner(decryptedString);
        stringScanner.useDelimiter("\n\n");

        // This first line should be the name. If this doesn't match, it is the wrong password (this is in case the
        // vault is empty to start. Something must be decrypted)
        if (!this.name.equals(stringScanner.next())) {
            stringScanner.close();
            inputStream.close();
            throw new NoSuchElementException("Incorrect password. Name invalid");
        }
        Scanner lineScanner;
        while (stringScanner.hasNext()) {
            lineScanner = new Scanner(stringScanner.next());
            lineScanner.useDelimiter("\n");

            String name = lineScanner.next();
            String username = lineScanner.next();
            String password = lineScanner.next();

            addPassword(name, username, password);

            lineScanner.close();
        }
        stringScanner.close();
        inputStream.close();
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

        // If the vaults directory doesn't exist yet, create it
        File file = new File(vaultDirectory);
        if (!file.exists()) {
            file.mkdir();
        }

        FileOutputStream outFile = new FileOutputStream(vaultDirectory + name + ".pmv");
        outFile.write(encryptedBytes);
        outFile.close();
    }

    /**
     * @return an unencrypted representation of the vault
     */
    @Override
    public String toString() {
        StringBuilder vaultBuilder = new StringBuilder();
        vaultBuilder.append(name);
        vaultBuilder.append("\n\n");

        for (String record: passwords.keySet()) {
            Password recordPassword = passwords.get(record);

            vaultBuilder.append(String.format("%s\n%s\n%s\n\n",
                    record, recordPassword.getUsername(), recordPassword.getPassword()));
        }

        return vaultBuilder.toString();
    }

    /**
     * @return the name of the vault
     */
    public String getName() {
        return name;
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

    /**
     * @return the set of record names
     */
    public Set<String> getRecords() {
        return passwords.keySet();
    }

    /**
     * Prints out a list of all the records
     */
    public void listRecords() {
        System.out.printf("Available records in '%s':\n", name);
        for (String record : passwords.keySet())
            System.out.println("\t" + record);
    }

    /**
     * @param name the name of a record we want to see if it is in the vault
     * @return true if the name is in the vault as a record
     */
    public boolean containsRecord(String name) {
        return passwords.containsKey(name);
    }

    /**
     * @param name the name of the password we want to retrieve
     * @return the password for the name
     */
    public String getPassword(String name) {
        return passwords.get(name).getPassword();
    }

    /**
     * @param name the name of the username we want to retrieve
     * @return the username for the name
     */
    public String getUsername(String name) {
        return passwords.get(name).getUsername();
    }

    /**
     * Deletes the vault by removing the file it is stored in
     */
    public void delete() {
        File file = new File(vaultDirectory + name + ".pmv");
        file.delete();
    }
}