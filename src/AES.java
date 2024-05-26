import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.ArrayList;
import java.util.Random;

/**
 * A class with static methods used to encrypt and decrypt with AES cryptography.
 * @author Hudson Hadley
 */
public class AES {
    /**
     * This is a lookup table for the AES encryption. To find the new byte, the first 4 bits are used as the row index,
     * and the last 4 bits are used as the column index. For example, S(11011001) = SBOX[13][9] = 0x61 = 00110101
     */
    public final static byte[][] SBOX = new byte[][] {
{b(0x63), b(0x7c), b(0x77), b(0x7b), b(0xf2), b(0x6b), b(0x6f), b(0xc5), b(0x30), b(0x01), b(0x67), b(0x2b), b(0xfe), b(0xd7), b(0xab), b(0x76)},
{b(0xca), b(0x82), b(0xc9), b(0x7d), b(0xfa), b(0x59), b(0x47), b(0xf0), b(0xad), b(0xd4), b(0xa2), b(0xaf), b(0x9c), b(0xa4), b(0x72), b(0xc0)},
{b(0xb7), b(0xfd), b(0x93), b(0x26), b(0x36), b(0x3f), b(0xf7), b(0xcc), b(0x34), b(0xa5), b(0xe5), b(0xf1), b(0x71), b(0xd8), b(0x31), b(0x15)},
{b(0x04), b(0xc7), b(0x23), b(0xc3), b(0x18), b(0x96), b(0x05), b(0x9a), b(0x07), b(0x12), b(0x80), b(0xe2), b(0xeb), b(0x27), b(0xb2), b(0x75)},
{b(0x09), b(0x83), b(0x2c), b(0x1a), b(0x1b), b(0x6e), b(0x5a), b(0xa0), b(0x52), b(0x3b), b(0xd6), b(0xb3), b(0x29), b(0xe3), b(0x2f), b(0x84)},
{b(0x53), b(0xd1), b(0x00), b(0xed), b(0x20), b(0xfc), b(0xb1), b(0x5b), b(0x6a), b(0xcb), b(0xbe), b(0x39), b(0x4a), b(0x4c), b(0x58), b(0xcf)},
{b(0xd0), b(0xef), b(0xaa), b(0xfb), b(0x43), b(0x4d), b(0x33), b(0x85), b(0x45), b(0xf9), b(0x02), b(0x7f), b(0x50), b(0x3c), b(0x9f), b(0xa8)},
{b(0x51), b(0xa3), b(0x40), b(0x8f), b(0x92), b(0x9d), b(0x38), b(0xf5), b(0xbc), b(0xb6), b(0xda), b(0x21), b(0x10), b(0xff), b(0xf3), b(0xd2)},
{b(0xcd), b(0x0c), b(0x13), b(0xec), b(0x5f), b(0x97), b(0x44), b(0x17), b(0xc4), b(0xa7), b(0x7e), b(0x3d), b(0x64), b(0x5d), b(0x19), b(0x73)},
{b(0x60), b(0x81), b(0x4f), b(0xdc), b(0x22), b(0x2a), b(0x90), b(0x88), b(0x46), b(0xee), b(0xb8), b(0x14), b(0xde), b(0x5e), b(0x0b), b(0xdb)},
{b(0xe0), b(0x32), b(0x3a), b(0x0a), b(0x49), b(0x06), b(0x24), b(0x5c), b(0xc2), b(0xd3), b(0xac), b(0x62), b(0x91), b(0x95), b(0xe4), b(0x79)},
{b(0xe7), b(0xc8), b(0x37), b(0x6d), b(0x8d), b(0xd5), b(0x4e), b(0xa9), b(0x6c), b(0x56), b(0xf4), b(0xea), b(0x65), b(0x7a), b(0xae), b(0x08)},
{b(0xba), b(0x78), b(0x25), b(0x2e), b(0x1c), b(0xa6), b(0xb4), b(0xc6), b(0xe8), b(0xdd), b(0x74), b(0x1f), b(0x4b), b(0xbd), b(0x8b), b(0x8a)},
{b(0x70), b(0x3e), b(0xb5), b(0x66), b(0x48), b(0x03), b(0xf6), b(0x0e), b(0x61), b(0x35), b(0x57), b(0xb9), b(0x86), b(0xc1), b(0x1d), b(0x9e)},
{b(0xe1), b(0xf8), b(0x98), b(0x11), b(0x69), b(0xd9), b(0x8e), b(0x94), b(0x9b), b(0x1e), b(0x87), b(0xe9), b(0xce), b(0x55), b(0x28), b(0xdf)},
{b(0x8c), b(0xa1), b(0x89), b(0x0d), b(0xbf), b(0xe6), b(0x42), b(0x68), b(0x41), b(0x99), b(0x2d), b(0x0f), b(0xb0), b(0x54), b(0xbb), b(0x16)}};


    /**
     * This is the inverse of the SBOX byte table.
     */
    public final static byte[][] inverseSBOX = new byte[][] {
{b(0x52), b(0x09), b(0x6a), b(0xd5), b(0x30), b(0x36), b(0xa5), b(0x38), b(0xbf), b(0x40), b(0xa3), b(0x9e), b(0x81), b(0xf3), b(0xd7), b(0xfb)},
{b(0x7c), b(0xe3), b(0x39), b(0x82), b(0x9b), b(0x2f), b(0xff), b(0x87), b(0x34), b(0x8e), b(0x43), b(0x44), b(0xc4), b(0xde), b(0xe9), b(0xcb)},
{b(0x54), b(0x7b), b(0x94), b(0x32), b(0xa6), b(0xc2), b(0x23), b(0x3d), b(0xee), b(0x4c), b(0x95), b(0x0b), b(0x42), b(0xfa), b(0xc3), b(0x43)},
{b(0x08), b(0x2e), b(0xa1), b(0x66), b(0x28), b(0xd9), b(0x24), b(0xb2), b(0x76), b(0x5b), b(0xa2), b(0x49), b(0x6d), b(0x8b), b(0xd1), b(0x25)},
{b(0x72), b(0xf8), b(0xf6), b(0x64), b(0x86), b(0x68), b(0x98), b(0x16), b(0xd4), b(0xa4), b(0x5c), b(0xcc), b(0x5d), b(0x65), b(0xb6), b(0x92)},
{b(0x6c), b(0x70), b(0x48), b(0x50), b(0xfd), b(0xed), b(0xb9), b(0xda), b(0x5e), b(0x15), b(0x46), b(0x57), b(0xa7), b(0x8d), b(0x9d), b(0x84)},
{b(0x90), b(0xd8), b(0xab), b(0x00), b(0x8c), b(0xbc), b(0xd3), b(0x0a), b(0xf7), b(0xe4), b(0x58), b(0x05), b(0xb8), b(0xb3), b(0x45), b(0x06)},
{b(0xd0), b(0x2c), b(0x1e), b(0x8f), b(0xca), b(0x3f), b(0x0f), b(0x02), b(0xc1), b(0xaf), b(0xbd), b(0x03), b(0x01), b(0x13), b(0x8a), b(0x6b)},
{b(0x31), b(0x91), b(0x11), b(0x41), b(0x4f), b(0x67), b(0xdc), b(0xea), b(0x97), b(0xf2), b(0xcf), b(0xce), b(0xf0), b(0xb4), b(0xe6), b(0x73)},
{b(0x96), b(0xac), b(0x74), b(0x22), b(0xe7), b(0xad), b(0x35), b(0x85), b(0xe2), b(0xf9), b(0x37), b(0xe8), b(0x1c), b(0x75), b(0xdf), b(0x6e)},
{b(0x47), b(0xf1), b(0x1a), b(0x71), b(0x1d), b(0x29), b(0xc5), b(0x89), b(0x6f), b(0xb7), b(0x62), b(0x0e), b(0xaa), b(0x18), b(0xbe), b(0x1b)},
{b(0xfc), b(0x56), b(0x3e), b(0x4b), b(0xc6), b(0xd2), b(0x79), b(0x20), b(0x9a), b(0xdb), b(0xc0), b(0xfe), b(0x78), b(0xcd), b(0x5a), b(0xf4)},
{b(0x1f), b(0xdd), b(0xa8), b(0x33), b(0x88), b(0x07), b(0xc7), b(0x31), b(0xb1), b(0x12), b(0x10), b(0x59), b(0x27), b(0x80), b(0xec), b(0x5f)},
{b(0x60), b(0x51), b(0x7f), b(0xa9), b(0x19), b(0x5b), b(0x4a), b(0x0d), b(0x2d), b(0xe5), b(0x7a), b(0x9f), b(0x93), b(0xc9), b(0x9c), b(0xef)},
{b(0xa0), b(0xe0), b(0x3b), b(0x4d), b(0xae), b(0x2a), b(0xf5), b(0xb0), b(0xc8), b(0xeb), b(0xbb), b(0x3c), b(0x83), b(0x53), b(0x99), b(0x61)},
{b(0x17), b(0x2b), b(0x04), b(0x7e), b(0xba), b(0x77), b(0xd6), b(0x26), b(0xe1), b(0x69), b(0x14), b(0x63), b(0x55), b(0x21), b(0x0c), b(0x7d)}};


    /**
     * Converts an integer into a byte
     * @param b the integer we want to convert
     * @return the integer as a byte
     */
    public static byte b(int b) {
        return (byte) b;
    }

    /**
     * Encrypts a byte array using AES
     * @param plaintext the byte array we want to encrypt
     * @param key the key which must be 128, 192, or 256 bits (16, 24, or 32 bytes)
     * @return the encrypted byte array
     * @throws IllegalArgumentException if the key is not 128, 192, or 256 bits (16, 24, or 32 bytes)
     */
    public static byte[] encrypt(byte[] plaintext, byte[] key) throws IllegalArgumentException {
        if (key.length != 16 && key.length != 24 && key.length != 32)
            throw new IllegalArgumentException("Invalid key size. Must be 128, 192, or 256 bits");

        // TODO finish method
        return new byte[]{};
    }

    /**
     * Decrypts a byte array using AES
     * @param ciphertext the byte array we want to decrypt
     * @param key the key which must be 128, 192, or 256 bits (16, 24, or 32 bytes)
     * @return the decrypted String
     * @throws IllegalArgumentException if the key is not 128, 192, or 256 bits (16, 24, or 32 bytes)
     */
    public static String decrypt(byte[] ciphertext, byte[] key) throws IllegalArgumentException {
        if (key.length != 16 && key.length != 24 && key.length != 32)
            throw new IllegalArgumentException("Invalid key size. Must be 128, 192, or 256 bits");

        // TODO finish method
        return "";
    }

    /**
     * Encrypts a byte array using AES
     * @param plaintext the String we want to encrypt
     * @param key the String we want to encrypt with
     * @param keySize AES can be done with a key size of 128, 192, or 256 bits
     * @throws IllegalArgumentException if the keySize is not 128, 192, or 256
     * @return the encrypted byte array
     */
    public static byte[] encrypt(String plaintext, String key, int keySize) throws IllegalArgumentException {
        return encrypt(stringToByteArray(plaintext), expandKey(key, keySize));
    }

    /**
     * Decrypts a byte array using AES
     * @param ciphertext the byte array we want to decrypt
     * @param key the String we want to decrypt with
     * @param keySize AES can be done with a key size of 128, 192, or 256 bits
     * @throws IllegalArgumentException if the keySize is not 128, 192, or 256
     * @return the decrypted String
     */
    public static String decrypt(byte[] ciphertext, String key, int keySize) throws IllegalArgumentException {
        return decrypt(ciphertext, expandKey(key, keySize));
    }

    /**
     * Applies the Rijndael S-box to a byte
     * @param b the byte we want to work with
     * @return the output of the S-box
     */
    public static byte S(byte b) {
        int row = (b & 0xf0) >>> 4; // Gets the first 4 bits of the byte
        int col = b & 0x0f; // Gets the last 4 bits of the byte

        return SBOX[row][col];
    }

    /**
     * Applies the inverse of the Rijndael S-box to a byte
     * @param b the byte we want to work with
     * @return the output of the inverse S-box
     */
    public static byte inverseS(byte b) {
        int row = (b & 0xf0) >>> 4; // Gets the first 4 bits of the byte
        int col = b & 0x0f; // Gets the last 4 bits of the byte

        return inverseSBOX[row][col];
    }

    /**
     * Expands a key to a certain bit length
     * @param key the String we want to expand
     * @param length the length we want the key to have in bits
     * @return the expanded key
     * @throws IllegalArgumentException if we are unable to generate the key
     */
    public static byte[] expandKey(String key, int length) throws IllegalArgumentException {
        Random randomSaltGenerator = new Random(71504);
        byte[] salt = new byte[16];
        randomSaltGenerator.nextBytes(salt);
        int iterations = 1024;

        PBEKeySpec spec = new PBEKeySpec(key.toCharArray(), salt, iterations, length);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

            return skf.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to generate key");
        }
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
