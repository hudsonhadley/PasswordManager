import java.io.File;
import java.io.IOException;
import java.sql.SQLOutput;
import java.text.NumberFormat;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Scanner;
import java.io.FilenameFilter;
import java.util.Set;

public class Main {
    /**
     * Gets a number min through max inclusive from the scanner.
     * @param min the smallest a number can be
     * @param max the most a number can be
     * @param scanner the scanner to get input
     * @return a number between min and max from the user
     * @throws IllegalArgumentException if min is greater than max
     */
    public static int getOption(int min, int max, Scanner scanner) {
        if (min > max) {
            throw new IllegalStateException("Min must be less than or equal to max");
        }
        int userPick;
        // Get a number between min and max from the user
        while (true) {
            try {
                userPick = Integer.parseInt(scanner.nextLine());

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
     * Gets the user to enter a password and confirm it
     * @param scanner the scanner we want to use for input
     * @return the confirmed password
     */
    public static String confirmPassword(Scanner scanner) {
        // Get the master password
        String password;
        String confirmedPassword;

        while (true) {
            System.out.print("Enter the password: ");
            password = scanner.nextLine();

            System.out.print("Please confirm your password: ");
            confirmedPassword = scanner.nextLine();

            if (!password.equals(confirmedPassword))
                System.out.println("Passwords must match");
            else
                break;
        }

        return password;
    }

    /**
     * Fetches a record from a vault with user input and prints it
     * @param scanner the scanner used for input
     * @param vault the vault we want to fetch from
     * @return the name of the record fetched
     */
    public static String fetchRecord(Scanner scanner, Vault vault) {
        String name;
        while (true) {
            System.out.print("Enter a record: ");
            name = scanner.nextLine();

            if (vault.containsRecord(name))
                break;
            else
                System.out.printf("'%s' not found in '%s'\n", name, vault.getName());
        }

        System.out.printf("%s: %s, %s", name, vault.getUsername(name), vault.getPassword(name));

        return name;
    }

    /**
     * Searches the project folder for vaults
     * @return a Set of Strings with vault names
     */
    public static Set<String> getVaultNames() {
        // This is the main project directory that holds src
        File projectDirectory = new File(".");

        String[] fileNames = projectDirectory.list();

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

    public static void main(String[] args) throws IOException, NoSuchFieldException {
        // Greeting
        // List options
            // Create new vault
            // Sign in to previous vault
            // Delete Vault
        Scanner userScanner = new Scanner(System.in);

        System.out.println("Welcome to My Password Manager!");
        while (true) {
            Set<String> vaults = getVaultNames();

            System.out.println("What would you like to do?");
            System.out.println("1. Create a new password vault");
            System.out.println("2. Sign in to a previous password vault");
            System.out.println("3. Quit");

            int userPick = getOption(1, 3, userScanner);

            if (userPick == 1) {

                String vaultName;
                // Get a vault name that is not already in use
                while (true) {
                    System.out.print("Enter a vault name: ");
                    vaultName = userScanner.nextLine();

                    if (!vaults.contains(vaultName))
                        break;
                    else
                        System.out.printf("'%s' already in use\n", vaultName);
                }

                String masterPassword = confirmPassword(userScanner);

                Vault vault = new Vault(vaultName, masterPassword);
                vault.writeToFile();
                System.out.println("Vault created successfully");

            } else if (userPick == 2) {
                String vaultName;
                while (true) {
                    System.out.print("Enter the name of a vault: ");
                    vaultName = userScanner.nextLine();

                    if (!vaults.contains(vaultName))
                        System.out.printf("'%s' vault not found", vaultName);
                    else
                        break;
                }

                System.out.println("Vault found");
                Vault vault = new Vault(vaultName);

                int strikes = 0; // If they incorrectly enter a password three times, send them back to the home screen
                // Get the password
                while (strikes < 3) {
                    System.out.print("Please enter the password: ");
                    String password = userScanner.nextLine();

                    if (vault.validatePassword(password))
                        break;

                    strikes++;
                }
                // If they got three strikes, send them back to the home screen
                if (strikes == 3)
                    break;

                System.out.println("Vault successfully signed in");
                vault.listRecords();

                // Operate within the vault
                boolean deleted = false;
                while (true) {
                    System.out.println("What would you like to do?");
                    System.out.println("1. Add an entry");
                    System.out.println("2. Edit an entry");
                    System.out.println("3. Find a password");
                    System.out.println("4. Delete vault");
                    System.out.println("5. Quit");


                    userPick = getOption(1, 5, userScanner);


                    // Add entry
                    if (userPick == 1) {
                        System.out.print("Enter the record name: ");
                        String record = userScanner.nextLine();

                        System.out.print("Enter the username: ");
                        String username = userScanner.nextLine();

                        String password = confirmPassword(userScanner);

                        vault.addPassword(record, username, password);
                        System.out.printf("Password for '%s' added\n", record);

                    } else if (userPick == 2) { // Edit entry

                        String name = fetchRecord(userScanner, vault);

                        System.out.println("What would you like to do?");
                        System.out.println("1. Edit the username");
                        System.out.println("2. Edit the password");
                        System.out.println("3. Delete the record");
                        System.out.println("4. Quit");

                        userPick = getOption(1, 4, userScanner);

                        if (userPick == 1) {
                            System.out.print("Enter the username: ");
                            String username = userScanner.nextLine();

                            vault.setPassword(name, username);
                        } else if (userPick == 2) {
                            String password = confirmPassword(userScanner);
                            vault.setPassword(name, password);
                        } else if (userPick == 3) {
                            vault.deletePassword(name);
                        } else { // userPick == 4
                            break;
                        }

                    } else if (userPick == 3) {
                        fetchRecord(userScanner, vault);
                    } else if (userPick == 4) {
                        System.out.println("Are you sure you would like to delete this vault? (y/n)");
                        while (true) {
                            char pick = userScanner.nextLine().toLowerCase().charAt(0);

                            if (pick == 'y') {
                                System.out.print("Please confirm password: ");
                                String password = userScanner.nextLine();

                                if (password.equals(vault.getMasterPassword())) {
                                    vault.delete();
                                    deleted = true;
                                }
                                else {
                                    System.out.println("Password incorrect. Vault not deleted");
                                }
                                break;

                            } else if (pick == 'n') {
                                break;
                            }
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
            } else { // userPick == 3
                break;
            }
        }
    }
}
