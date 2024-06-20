import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * A class full of static methods that hashes strings using the MD5 hashing algorithm.
 * @author Hudson Hadley
 */
public class MD5 {
    /**
     * Hashes the byte array using MD5
     * @param bytes the bytes we want to hash
     * @return the hashed bytes
     */
    public static byte[] hash(byte[] bytes) {
        // Block it with 512-bit (64-byte) blocks
        byte[] paddedBytes = pad(bytes);
        System.out.println(Arrays.toString(paddedBytes));

        return new byte[]{};
    }

    /**
     * Hashes a String by converting to bytes and using MD5
     * @param input the String we want to hash
     * @return the hashed bytes
     */
    public static byte[] hash(String input) {
        byte[] bytes = stringToByteArray(input);
        return hash(bytes);
    }



    /**
     * Pads the end of a byte array to be the desired amount of bytes divisible by. For example if 16 is the desired
     * byte divisibility, it will pad onto the byte array until the length is divisible by 16
     * @param bytes the byte array we want to pad
     * @param divisibility the divisibility we require
     * @return the padded byte array
     * @throws IllegalArgumentException if the divisibility is less than 1
     */
    private static byte[] pad(byte[] bytes, int divisibility) throws IllegalArgumentException {
        if (divisibility < 1)
            throw new IllegalArgumentException("Divisibility must be positive");

        ArrayList<Byte> paddedBytes = new ArrayList<>();
        for (byte aByte : bytes) {
            paddedBytes.add(aByte);
        }

        // Add a 10000000
        paddedBytes.add(b(0x80));

        // Keep adding 00000000 til we reach the divisibility
        while (paddedBytes.size() % divisibility != 0)
            paddedBytes.add(b(0x00));

        byte[] newBytes = new byte[paddedBytes.size()];

        for (int i = 0; i < paddedBytes.size(); i++)
            newBytes[i] = paddedBytes.get(i);

        return newBytes;
    }

    /**
     * Pads the end of a byte array as is custom for MD5 with the length included.
     * @param bytes the byte array we want to pad
     * @return the padded byte array
     */
    private static byte[] pad(byte[] bytes) {
        byte[] paddedBytes = pad(bytes, 64); // Make its 512-bits (64-bytes)

        // We need to change the last 8 bytes (64 bits) to be the length of the original message mod 2^64
        byte[] length = intToByteArray(bytes.length * 8, 8);
        for (int i = 0; i < length.length; i++) {
            paddedBytes[paddedBytes.length - 9 + i] = length[i];
        }

        return paddedBytes;
    }

    /**
     * Converts a given integer into a byte array with a certain capacity. If the input exceeds the capacity, it will
     * wrap into the set amount of bytes allowed
     * @param input the integer we want to convert
     * @param capacity the maximum amount of bytes we want to use to represent the integer
     * @return a byte array representing the wrapped integer
     */
    public static byte[] intToByteArray(int input, int capacity) {
        input %= (int) Math.pow(2, capacity * 8); // Wrap the input, so we can fit it into the given bytes allowed

        // This will be initialized with all 0s
        byte[] bytes = new byte[capacity];

        // Now we need to fill the last bytes with the input in bytes
        byte[] inputInBytes = BigInteger.valueOf(input).toByteArray();
        int startIndex = bytes.length - inputInBytes.length;
        for (int i = 0; i < inputInBytes.length; i++) {
            bytes[startIndex + i] = inputInBytes[i];
        }

        return bytes;
    }

    /**
     * Converts a given String to a byte array
     * @param input the String we want to convert
     * @return a byte array representing the String
     */
    private static byte[] stringToByteArray(String input) {
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
     * Blocks the given byte into certain block sizes
     * @param bytes the byte we want to block up
     * @param blockSize the block size we want to block with
     * @return the blocks of the byte array given
     * @throws IllegalArgumentException if the byte array cannot be blocked
     */
    private static byte[][] makeBlock(byte[] bytes, int blockSize) {
        if (bytes.length % blockSize != 0)
            throw new IllegalArgumentException("byte array cannot be blocked. Invalid size.");

        byte[][] blocks = new byte[bytes.length / blockSize][blockSize];

        for (int i = 0; i < bytes.length / blockSize; i++) {
            for (int j = 0; j < 16; j++) {
                blocks[i][j] = bytes[i * blockSize + j];
            }
        }

        return blocks;
    }

    /**
     * Converts an integer into a byte
     * @param b the integer we want to convert
     * @return the integer as a byte
     */
    private static byte b(int b) {
        return (byte) b;
    }
}
