import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;

/**
 * A class with static methods used to encrypt and decrypt with AES cryptography.
 * @author Hudson Hadley
 */
public class AES {
    /**
     * Encrypts a byte array using AES
     * @param plaintext the byte array we want to encrypt
     * @param key the 128-bit (16-byte) key we want to encrypt with
     * @return the encrypted byte array
     * @throws IllegalArgumentException if the key is not 128-bits
     */
    public static byte[] encrypt(byte[] plaintext, byte[] key) throws IllegalArgumentException {
        // TODO finish method
        return new byte[]{};
    }

    /**
     * Decrypts a byte array using AES
     * @param ciphertext the byte array we want to decrypt
     * @param key the 128-bit (16-byte) key we want to decrypt with
     * @return the decrypted String
     * @throws IllegalArgumentException if the key is not 128-bits
     */
    public static String decrypt(byte[] ciphertext, byte[] key) throws IllegalArgumentException {
        // TODO finish method
        return "";
    }

    /**
     * Encrypts a byte array using AES
     * @param plaintext the String we want to encrypt
     * @param key the String we want to encrypt with
     * @return the encrypted byte array
     * @throws IllegalArgumentException if the key cannot be made 128-bits
     */
    public static byte[] encrypt(String plaintext, String key) throws IllegalArgumentException {
        return encrypt(stringToByteArray(plaintext), expandKey(key, 128));
    }

    /**
     * Decrypts a byte array using AES
     * @param ciphertext the byte array we want to decrypt
     * @param key the String we want to decrypt with
     * @return the decrypted String
     * @throws IllegalArgumentException if the key cannot be made 128-bits
     */
    public static String decrypt(byte[] ciphertext, String key) {
        return decrypt(ciphertext, expandKey(key, 128));
    }

    /**
     * Expands a key to a certain byte length
     * @param key the String we want to expand
     * @param length the length we want to expand to
     * @return the expanded key
     */
    public static byte[] expandKey(String key, int length) {
        // TODO finish method
        return new byte[]{};
    }

    /**
     * Converts a given String to a byte array
     * @param input the String we want to convert
     * @return a byte array representing the String
     */
    public static byte[] stringToByteArray(String input) {
        ArrayList<Byte> bytes = new ArrayList<>();

        for (int i = 0; i < input.length(); i++) {
            bytes.add((byte) input.charAt(i));
        }

        byte[] byteArray = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) {
            byteArray[i] = bytes.get(i);
        }

        return byteArray;
    }

    /**
     * Converts a given byte array to a String
     * @param input the byte array we want to convert
     * @return a String representation of the byte array
     */
    public static String byteArraytoString(byte[] input) {
        StringBuilder stringBuilder = new StringBuilder();

        for (byte b : input) {
            stringBuilder.append(Character.toString(b));
        }

        return stringBuilder.toString();
    }

}
