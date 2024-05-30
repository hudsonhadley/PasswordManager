import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class Main {
    /**
     * Gets a number min through max inclusive from the console.
     * @param min the smallest a number can be
     * @param max the most a number can be
     * @param console the console to get input
     * @return a number between min and max from the user
     * @throws IllegalArgumentException if min is greater than max
     */
    public static int getOption(int min, int max, Console console) {
        if (min > max) {
            throw new IllegalStateException("Min must be less than or equal to max");
        }
        int userPick;
        // Get a number between min and max from the user
        while (true) {
            try {
                userPick = Integer.parseInt(console.readLine());

                if (min <= userPick && userPick <= max)
                    break;
                else
                    System.out.printf("Please enter an option %d-%d\n", min, max);
            } catch (NumberFormatException nfe) {
                System.out.printf("Please enter an option %d-%d\n", min, max);
            }
        }

        return userPick;
    }

    /**
     * Gets a line hidden from the console
     * @param console the console we get input from
     * @param prompt the prompt we want to give to the user
     * @return the string typed in
     */
    public static String getHiddenLine(Console console, String prompt) {
        char[] charPassword = console.readPassword(prompt);
        return new String(charPassword);
    }

    /**
     * Gets the user to enter a password and confirm it
     * @param console the console we want to use for input
     * @return the confirmed password
     */
    public static String confirmPassword(Console console) {
        // Get the master password
        String password;
        String confirmedPassword;

        while (true) {
            password = getHiddenLine(console, "Enter the password: ");

            confirmedPassword = getHiddenLine(console, "Please confirm password: ");

            if (!password.equals(confirmedPassword)) {
                System.out.println("Passwords must match");
                System.out.println();
            } else
                break;
        }

        return password;
    }

    /**
     * Fetches a record from a vault with user input and prints it
     * @param console the console used for input
     * @param vault the vault we want to fetch from
     * @return the name of the record fetched
     */
    public static String fetchRecord(Console console, Vault vault) {
        System.out.println();
        vault.listRecords();
        System.out.println();

        String name;
        while (true) {
            System.out.print("Enter a record: ");
            name = console.readLine();

            if (vault.containsRecord(name))
                break;
            else
                System.out.printf("'%s' not found in '%s'\n", name, vault.getName());
        }

        System.out.println();
        System.out.printf("%s:\n\tUsername: %s\n\tPassword: %s\n", name, vault.getUsername(name), vault.getPassword(name));

        return name;
    }

    /**
     * Searches the project folder for vaults
     * @return a Set of Strings with vault names
     */
    public static Set<String> getVaultNames() {
        String vaultDirectory = System.getProperty("java.class.path") + "/../../../vaults";
        File vaults = new File(vaultDirectory);

        String[] fileNames = vaults.list();

        if (fileNames == null)
            return new HashSet<>();

        Set<String> names = new HashSet<>();

        for (String fileName : fileNames) {
            int endingStart = fileName.length() - 1;

            // Keep adding until we reach the '.' or run out of characters
            while (endingStart > 0 && fileName.charAt(endingStart) != '.')
                endingStart--;

            // Divide the string into the name and the ending
            String ending = fileName.substring(endingStart);
            String name = fileName.substring(0, endingStart);

            if (ending.equals(".pmv"))
                names.add(name);
        }

        return names;
    }

    /**
     * Prints a line of "-" to the screen
     */
    public static void printLine() {
        int amount = 30;

        for (int i = 0; i < amount; i++) {
            System.out.print("-");
        }
        System.out.println();
    }

    public static void main(String[] args) throws IOException, NoSuchFieldException {
        Console console = System.console();

        System.out.println("Welcome to My Password Manager!");
        while (true) {
            Set<String> vaults = getVaultNames();

            printLine();
            System.out.println("What would you like to do?");
            System.out.println("1. Create a new password vault");
            System.out.println("2. Sign in to a previous password vault");
            System.out.println("3. Quit");

            int userPick = getOption(1, 3, console);

            // Create new vault
            if (userPick == 1) {
                printLine();

                String vaultName;
                // Get a vault name that is not already in use
                while (true) {
                    System.out.print("Enter a vault name: ");
                    vaultName = console.readLine();

                    if (!vaults.contains(vaultName))
                        break;
                    else
                        System.out.printf("'%s' already in use\n", vaultName);
                }

                String masterPassword = confirmPassword(console);

                Vault vault = new Vault(vaultName, masterPassword);
                vault.writeToFile();
                System.out.println();
                System.out.println("Vault created successfully");

                // Sign in to vault
            } else if (userPick == 2) {
                printLine();
                // If there are no vaults to sign in to
                if (vaults.isEmpty()) {
                    System.out.println("No vaults saved");
                    System.out.println();
                } else {
                    System.out.println("Available vaults:");
                    for (String vault: vaults)
                        System.out.println("\t" + vault);
                    System.out.println();

                    String vaultName;
                    while (true) {
                        System.out.print("Enter the name of a vault: ");
                        vaultName = console.readLine();

                        if (!vaults.contains(vaultName)) {
                            System.out.printf("'%s' vault not found\n", vaultName);
                        System.out.println();
                        } else
                            break;
                    }

                    Vault vault = new Vault(vaultName);

                    int strikes = 0; // If they incorrectly enter a password three times, send them back to the home screen
                    // Get the password
                    while (strikes < 3) {
                        String password = getHiddenLine(console, "Please enter the password: ");

                        if (vault.validatePassword(password))
                            break;

                        System.out.println("Incorrect");
                        System.out.println();
                        strikes++;
                    }
                    if (strikes == 3) {
                        System.out.println("Please try a different vault");
                    } else {

                        System.out.println();
                        System.out.println("Vault successfully signed in");


                        // Operate within the vault
                        boolean deleted = false;
                        while (true) {
                            printLine();
                            System.out.println("What would you like to do?");
                            System.out.println("1. Add an entry");
                            System.out.println("2. Edit an entry");
                            System.out.println("3. Find a password");
                            System.out.println("4. Delete vault");
                            System.out.println("5. Quit");


                            userPick = getOption(1, 5, console);
                            System.out.println();


                            // Add entry
                            if (userPick == 1) {
                                printLine();

                                String record;
                                while (true) {
                                    System.out.print("Enter the record name: ");
                                    record = console.readLine();

                                    if (vault.containsRecord(record)) {
                                        System.out.printf("'%s' already contains '%s'\n", vaultName, record);
                                        System.out.println();
                                    } else
                                        break;
                                }

                                System.out.print("Enter the username: ");
                                String username = console.readLine();

                                String password = confirmPassword(console);

                                vault.addPassword(record, username, password);
                                System.out.println();
                                System.out.printf("Password for '%s' added\n", record);

                            } else if (userPick == 2) { // Edit entry
                                printLine();
                                if (vault.getRecords().isEmpty()) {
                                    System.out.println("No available records");
                                    System.out.println();
                                } else {
                                    String name = fetchRecord(console, vault);

                                    System.out.println("What would you like to do?");
                                    System.out.println("1. Edit the username");
                                    System.out.println("2. Edit the password");
                                    System.out.println("3. Delete the record");
                                    System.out.println("4. Quit");

                                    userPick = getOption(1, 4, console);
                                    System.out.println();

                                    if (userPick == 1) {
                                        printLine();
                                        System.out.print("Enter the username: ");
                                        String username = console.readLine();

                                        vault.setUsername(name, username);
                                        System.out.printf("Username updated for '%s'\n", name);
                                    } else if (userPick == 2) {
                                        printLine();
                                        String password = confirmPassword(console);
                                        vault.setPassword(name, password);
                                        System.out.printf("Password updated for '%s'\n", name);
                                    } else if (userPick == 3) {
                                        printLine();
                                        vault.deletePassword(name);
                                    } // If they pick 4, we will do nothing
                                }
                            } else if (userPick == 3) {
                                printLine();
                                if (vault.getRecords().isEmpty()) {
                                    System.out.println("No available records");
                                    System.out.println();
                                } else {
                                    fetchRecord(console, vault);
                                }
                            } else if (userPick == 4) {
                                printLine();
                                System.out.println("Are you sure you would like to delete this vault? (y/n)");
                                while (true) {
                                    char pick = console.readLine().toLowerCase().charAt(0);

                                    if (pick == 'y') {
                                        String password = getHiddenLine(console, "Please confirm password: ");

                                        if (password.equals(vault.getMasterPassword())) {
                                            System.out.printf("'%s' deleted\n", vaultName);
                                            System.out.println();
                                            vault.delete();
                                            deleted = true;
                                        } else {
                                            System.out.println("Password incorrect. Vault not deleted");
                                        }
                                        break;

                                    } else if (pick == 'n') {
                                        break;
                                    }
                                    System.out.println();
                                }

                                // If we deleted the vault, we want to go back home
                                if (deleted)
                                    break;
                            } else { // userPick == 5
                                // Before we quit the vault, we need to save where we left off
                                vault.writeToFile();
                                break;
                            }
                        }
                    }
                }
            } else { // userPick == 3
                printLine();
                break;
            }
        }
    }
}
