import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;

/**
 * A class full of static methods that hashes strings using the MD5 hashing algorithm.
 * @author Hudson Hadley
 */
public class MD5 {
    /**
     * The shift amounts we use for each round. SHIFT_AMOUNTS[i] is used in round i.
     */
    private final static int[] SHIFT_AMOUNTS = new int[] {
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    };

    /**
     * The round constants used for each round. ROUND_CONSTANTS[i] is used for round i.
     */
    private final static int[] ROUND_CONSTANTS = new int[] {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };

    /**
     * Hashes the byte array using MD5
     * @param bytes the bytes we want to hash
     * @return the hashed bytes
     */
    public static byte[] hash(byte[] bytes) {
        // Block it with 512-bit (64-byte) blocks
        byte[] paddedBytes = pad(bytes);
        byte[][] blocks = makeBlock(paddedBytes, 64); // 512-bit block size (64-byte block size)

        int a0 = 0x67452301;
        int b0 = 0xefcdab89;
        int c0 = 0x98badcfe;
        int d0 = 0x10325476;

        // For each block
        for (byte[] block : blocks) {
            byte[][] chunks = makeBlock(block, 4);

            int A = a0;
            int B = b0;
            int C = c0;
            int D = d0;

            for (int i = 0; i < 64; i++) {
//                System.out.printf("\nROUND %d\n", i);
//                System.out.printf("A: %d\n", A);
//                System.out.printf("B: %d\n", B);
//                System.out.printf("C: %d\n", C);
//                System.out.printf("D: %d\n", D);
                int F;
                int g;

                if (i < 16) {
                    F = (B & C) | (~B & D);
                    g = i;
                } else if (i < 32) {
                    F = (D & B) | (~D & C);
                    g = (5 * i + 1) % 16;
                } else if (i < 48) {
                    F = B ^ C ^ D;
                    g = (3 * i + 5) % 16;
                } else {
                    F = C ^ (B | ~D);
                    g = (7 * i) % 16;
                }

                F = (F + A + ROUND_CONSTANTS[i] + getInt(chunks[g])) % (int) Math.pow(2, 32);

                int dTemp = D;
                D = C;
                C = B;
                B = (B + Integer.rotateLeft(F, SHIFT_AMOUNTS[i]));
                A = dTemp;
            }

            a0 += A;
            b0 += B;
            c0 += C;
            d0 += D;
        }
        // Translate the 4 32-bit words into a 128-bit byte array
        ByteBuffer b = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(a0);
        b.putInt(b0);
        b.putInt(c0);
        b.putInt(d0);

        return b.array();
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
     * Gets an integer represented by a four byte word
     * @param word a four byte word
     * @return the integer represented by the four byte word
     * @throws IllegalArgumentException if the word is not four bytes
     */
    private static int getInt(byte[] word) throws IllegalArgumentException {
        if (word.length != 4)
            throw new IllegalArgumentException("Invalid size");

        return (Byte.toUnsignedInt(word[3]) << 24) |
               (Byte.toUnsignedInt(word[2]) << 16) |
               (Byte.toUnsignedInt(word[1]) << 8 ) |
               (Byte.toUnsignedInt(word[0]));
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

        // If we start at a divisibility, we want to add more
        paddedBytes.add(b(0x00));

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
        // Add a one to the end
        byte[] bytesWith1 = new byte[bytes.length + 1];
        for (int i = 0; i < bytes.length; i++) {
            bytesWith1[i] = bytes[i];
        }
        bytesWith1[bytesWith1.length - 1] = b(0x80);

        byte[] paddedBytes = pad(bytesWith1, 64); // Make it 512-bits (64-bytes)

        // If we get a length that is less than 64 (meaning it needs padding until % 64), but it won't have enough room
        // for the length of the length in binary (it is more than 64 - 8), then we need to add another set of 0s
        if (bytes.length % 64 > 64 - 8)
            paddedBytes = pad(paddedBytes, 64);

        // We need to change the last 8 bytes (64 bits) to be the length of the original message mod 2^64
        ByteBuffer b = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(bytes.length * 8);
        byte[] length = b.array();

        for (int i = 0; i < 8; i++) {
            paddedBytes[paddedBytes.length - i - 1] = length[length.length - i - 1];
        }

        return paddedBytes;
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
            for (int j = 0; j < blockSize; j++) {
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

    /**
     * Converts a byte array into hex code
     * @param bytes the bytes we want to convert
     */
    public static String getHexCode(byte[] bytes) {
        StringBuilder hexBuilder = new StringBuilder();

        for (byte aByte : bytes) {
            int unsignedInt = Byte.toUnsignedInt(aByte);

            // If the result is just 8, we want a 08 since this is part of a greater number
            if (unsignedInt < 0x10)
                hexBuilder.append("0");

            hexBuilder.append(Integer.toHexString(unsignedInt));

        }

        return hexBuilder.toString();
    }
}
