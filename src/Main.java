import java.io.File;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Scanner;
import java.io.FilenameFilter;
import java.util.Set;

public class Main {
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
    public static void main(String[] args) {

    }
}
