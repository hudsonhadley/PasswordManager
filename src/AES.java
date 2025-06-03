import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/**
 * A class with static methods used to encrypt and decrypt with AES-128 cryptography.
 * @author Hudson Hadley
 */
public class AES {
    /**
     * This is used for multiplication by 2 in the Galois field GF(256) such that TABLE_2[n] is equal to 2 * n.
     */
    private final static byte[] TABLE_2 = new byte[] {
b(0x00), b(0x02), b(0x04), b(0x06), b(0x08), b(0x0a), b(0x0c), b(0x0e), b(0x10), b(0x12), b(0x14), b(0x16), b(0x18), b(0x1a), b(0x1c), b(0x1e),
b(0x20), b(0x22), b(0x24), b(0x26), b(0x28), b(0x2a), b(0x2c), b(0x2e), b(0x30), b(0x32), b(0x34), b(0x36), b(0x38), b(0x3a), b(0x3c), b(0x3e),
b(0x40), b(0x42), b(0x44), b(0x46), b(0x48), b(0x4a), b(0x4c), b(0x4e), b(0x50), b(0x52), b(0x54), b(0x56), b(0x58), b(0x5a), b(0x5c), b(0x5e),
b(0x60), b(0x62), b(0x64), b(0x66), b(0x68), b(0x6a), b(0x6c), b(0x6e), b(0x70), b(0x72), b(0x74), b(0x76), b(0x78), b(0x7a), b(0x7c), b(0x7e),
b(0x80), b(0x82), b(0x84), b(0x86), b(0x88), b(0x8a), b(0x8c), b(0x8e), b(0x90), b(0x92), b(0x94), b(0x96), b(0x98), b(0x9a), b(0x9c), b(0x9e),
b(0xa0), b(0xa2), b(0xa4), b(0xa6), b(0xa8), b(0xaa), b(0xac), b(0xae), b(0xb0), b(0xb2), b(0xb4), b(0xb6), b(0xb8), b(0xba), b(0xbc), b(0xbe),
b(0xc0), b(0xc2), b(0xc4), b(0xc6), b(0xc8), b(0xca), b(0xcc), b(0xce), b(0xd0), b(0xd2), b(0xd4), b(0xd6), b(0xd8), b(0xda), b(0xdc), b(0xde),
b(0xe0), b(0xe2), b(0xe4), b(0xe6), b(0xe8), b(0xea), b(0xec), b(0xee), b(0xf0), b(0xf2), b(0xf4), b(0xf6), b(0xf8), b(0xfa), b(0xfc), b(0xfe),
b(0x1b), b(0x19), b(0x1f), b(0x1d), b(0x13), b(0x11), b(0x17), b(0x15), b(0x0b), b(0x09), b(0x0f), b(0x0d), b(0x03), b(0x01), b(0x07), b(0x05),
b(0x3b), b(0x39), b(0x3f), b(0x3d), b(0x33), b(0x31), b(0x37), b(0x35), b(0x2b), b(0x29), b(0x2f), b(0x2d), b(0x23), b(0x21), b(0x27), b(0x25),
b(0x5b), b(0x59), b(0x5f), b(0x5d), b(0x53), b(0x51), b(0x57), b(0x55), b(0x4b), b(0x49), b(0x4f), b(0x4d), b(0x43), b(0x41), b(0x47), b(0x45),
b(0x7b), b(0x79), b(0x7f), b(0x7d), b(0x73), b(0x71), b(0x77), b(0x75), b(0x6b), b(0x69), b(0x6f), b(0x6d), b(0x63), b(0x61), b(0x67), b(0x65),
b(0x9b), b(0x99), b(0x9f), b(0x9d), b(0x93), b(0x91), b(0x97), b(0x95), b(0x8b), b(0x89), b(0x8f), b(0x8d), b(0x83), b(0x81), b(0x87), b(0x85),
b(0xbb), b(0xb9), b(0xbf), b(0xbd), b(0xb3), b(0xb1), b(0xb7), b(0xb5), b(0xab), b(0xa9), b(0xaf), b(0xad), b(0xa3), b(0xa1), b(0xa7), b(0xa5),
b(0xdb), b(0xd9), b(0xdf), b(0xdd), b(0xd3), b(0xd1), b(0xd7), b(0xd5), b(0xcb), b(0xc9), b(0xcf), b(0xcd), b(0xc3), b(0xc1), b(0xc7), b(0xc5),
b(0xfb), b(0xf9), b(0xff), b(0xfd), b(0xf3), b(0xf1), b(0xf7), b(0xf5), b(0xeb), b(0xe9), b(0xef), b(0xed), b(0xe3), b(0xe1), b(0xe7), b(0xe5)};

    /**
     * This is used for multiplication by 3 in the Galois field GF(256) such that TABLE_3[n] is equal to 3 * n.
     */
    private final static byte[] TABLE_3 = new byte[] {
b(0x00), b(0x03), b(0x06), b(0x05), b(0x0c), b(0x0f), b(0x0a), b(0x09), b(0x18), b(0x1b), b(0x1e), b(0x1d), b(0x14), b(0x17), b(0x12), b(0x11),
b(0x30), b(0x33), b(0x36), b(0x35), b(0x3c), b(0x3f), b(0x3a), b(0x39), b(0x28), b(0x2b), b(0x2e), b(0x2d), b(0x24), b(0x27), b(0x22), b(0x21),
b(0x60), b(0x63), b(0x66), b(0x65), b(0x6c), b(0x6f), b(0x6a), b(0x69), b(0x78), b(0x7b), b(0x7e), b(0x7d), b(0x74), b(0x77), b(0x72), b(0x71),
b(0x50), b(0x53), b(0x56), b(0x55), b(0x5c), b(0x5f), b(0x5a), b(0x59), b(0x48), b(0x4b), b(0x4e), b(0x4d), b(0x44), b(0x47), b(0x42), b(0x41),
b(0xc0), b(0xc3), b(0xc6), b(0xc5), b(0xcc), b(0xcf), b(0xca), b(0xc9), b(0xd8), b(0xdb), b(0xde), b(0xdd), b(0xd4), b(0xd7), b(0xd2), b(0xd1),
b(0xf0), b(0xf3), b(0xf6), b(0xf5), b(0xfc), b(0xff), b(0xfa), b(0xf9), b(0xe8), b(0xeb), b(0xee), b(0xed), b(0xe4), b(0xe7), b(0xe2), b(0xe1),
b(0xa0), b(0xa3), b(0xa6), b(0xa5), b(0xac), b(0xaf), b(0xaa), b(0xa9), b(0xb8), b(0xbb), b(0xbe), b(0xbd), b(0xb4), b(0xb7), b(0xb2), b(0xb1),
b(0x90), b(0x93), b(0x96), b(0x95), b(0x9c), b(0x9f), b(0x9a), b(0x99), b(0x88), b(0x8b), b(0x8e), b(0x8d), b(0x84), b(0x87), b(0x82), b(0x81),
b(0x9b), b(0x98), b(0x9d), b(0x9e), b(0x97), b(0x94), b(0x91), b(0x92), b(0x83), b(0x80), b(0x85), b(0x86), b(0x8f), b(0x8c), b(0x89), b(0x8a),
b(0xab), b(0xa8), b(0xad), b(0xae), b(0xa7), b(0xa4), b(0xa1), b(0xa2), b(0xb3), b(0xb0), b(0xb5), b(0xb6), b(0xbf), b(0xbc), b(0xb9), b(0xba),
b(0xfb), b(0xf8), b(0xfd), b(0xfe), b(0xf7), b(0xf4), b(0xf1), b(0xf2), b(0xe3), b(0xe0), b(0xe5), b(0xe6), b(0xef), b(0xec), b(0xe9), b(0xea),
b(0xcb), b(0xc8), b(0xcd), b(0xce), b(0xc7), b(0xc4), b(0xc1), b(0xc2), b(0xd3), b(0xd0), b(0xd5), b(0xd6), b(0xdf), b(0xdc), b(0xd9), b(0xda),
b(0x5b), b(0x58), b(0x5d), b(0x5e), b(0x57), b(0x54), b(0x51), b(0x52), b(0x43), b(0x40), b(0x45), b(0x46), b(0x4f), b(0x4c), b(0x49), b(0x4a),
b(0x6b), b(0x68), b(0x6d), b(0x6e), b(0x67), b(0x64), b(0x61), b(0x62), b(0x73), b(0x70), b(0x75), b(0x76), b(0x7f), b(0x7c), b(0x79), b(0x7a),
b(0x3b), b(0x38), b(0x3d), b(0x3e), b(0x37), b(0x34), b(0x31), b(0x32), b(0x23), b(0x20), b(0x25), b(0x26), b(0x2f), b(0x2c), b(0x29), b(0x2a),
b(0x0b), b(0x08), b(0x0d), b(0x0e), b(0x07), b(0x04), b(0x01), b(0x02), b(0x13), b(0x10), b(0x15), b(0x16), b(0x1f), b(0x1c), b(0x19), b(0x1a)};

    /**
     * This is used for multiplication by 9 in the Galois field GF(256) such that TABLE_9[n] is equal to 9 * n.
     */
    private final static byte[] TABLE_9 = new byte[] {
b(0x00), b(0x09), b(0x12), b(0x1b), b(0x24), b(0x2d), b(0x36), b(0x3f), b(0x48), b(0x41), b(0x5a), b(0x53), b(0x6c), b(0x65), b(0x7e), b(0x77),
b(0x90), b(0x99), b(0x82), b(0x8b), b(0xb4), b(0xbd), b(0xa6), b(0xaf), b(0xd8), b(0xd1), b(0xca), b(0xc3), b(0xfc), b(0xf5), b(0xee), b(0xe7),
b(0x3b), b(0x32), b(0x29), b(0x20), b(0x1f), b(0x16), b(0x0d), b(0x04), b(0x73), b(0x7a), b(0x61), b(0x68), b(0x57), b(0x5e), b(0x45), b(0x4c),
b(0xab), b(0xa2), b(0xb9), b(0xb0), b(0x8f), b(0x86), b(0x9d), b(0x94), b(0xe3), b(0xea), b(0xf1), b(0xf8), b(0xc7), b(0xce), b(0xd5), b(0xdc),
b(0x76), b(0x7f), b(0x64), b(0x6d), b(0x52), b(0x5b), b(0x40), b(0x49), b(0x3e), b(0x37), b(0x2c), b(0x25), b(0x1a), b(0x13), b(0x08), b(0x01),
b(0xe6), b(0xef), b(0xf4), b(0xfd), b(0xc2), b(0xcb), b(0xd0), b(0xd9), b(0xae), b(0xa7), b(0xbc), b(0xb5), b(0x8a), b(0x83), b(0x98), b(0x91),
b(0x4d), b(0x44), b(0x5f), b(0x56), b(0x69), b(0x60), b(0x7b), b(0x72), b(0x05), b(0x0c), b(0x17), b(0x1e), b(0x21), b(0x28), b(0x33), b(0x3a),
b(0xdd), b(0xd4), b(0xcf), b(0xc6), b(0xf9), b(0xf0), b(0xeb), b(0xe2), b(0x95), b(0x9c), b(0x87), b(0x8e), b(0xb1), b(0xb8), b(0xa3), b(0xaa),
b(0xec), b(0xe5), b(0xfe), b(0xf7), b(0xc8), b(0xc1), b(0xda), b(0xd3), b(0xa4), b(0xad), b(0xb6), b(0xbf), b(0x80), b(0x89), b(0x92), b(0x9b),
b(0x7c), b(0x75), b(0x6e), b(0x67), b(0x58), b(0x51), b(0x4a), b(0x43), b(0x34), b(0x3d), b(0x26), b(0x2f), b(0x10), b(0x19), b(0x02), b(0x0b),
b(0xd7), b(0xde), b(0xc5), b(0xcc), b(0xf3), b(0xfa), b(0xe1), b(0xe8), b(0x9f), b(0x96), b(0x8d), b(0x84), b(0xbb), b(0xb2), b(0xa9), b(0xa0),
b(0x47), b(0x4e), b(0x55), b(0x5c), b(0x63), b(0x6a), b(0x71), b(0x78), b(0x0f), b(0x06), b(0x1d), b(0x14), b(0x2b), b(0x22), b(0x39), b(0x30),
b(0x9a), b(0x93), b(0x88), b(0x81), b(0xbe), b(0xb7), b(0xac), b(0xa5), b(0xd2), b(0xdb), b(0xc0), b(0xc9), b(0xf6), b(0xff), b(0xe4), b(0xed),
b(0x0a), b(0x03), b(0x18), b(0x11), b(0x2e), b(0x27), b(0x3c), b(0x35), b(0x42), b(0x4b), b(0x50), b(0x59), b(0x66), b(0x6f), b(0x74), b(0x7d),
b(0xa1), b(0xa8), b(0xb3), b(0xba), b(0x85), b(0x8c), b(0x97), b(0x9e), b(0xe9), b(0xe0), b(0xfb), b(0xf2), b(0xcd), b(0xc4), b(0xdf), b(0xd6),
b(0x31), b(0x38), b(0x23), b(0x2a), b(0x15), b(0x1c), b(0x07), b(0x0e), b(0x79), b(0x70), b(0x6b), b(0x62), b(0x5d), b(0x54), b(0x4f), b(0x46)};

    /**
     * This is used for multiplication by b (or 11) in the Galois field GF(256) such that TABLE_B[n] is equal to b * n.
     */
    private final static byte[] TABLE_B = new byte[] {
b(0x00), b(0x0b), b(0x16), b(0x1d), b(0x2c), b(0x27), b(0x3a), b(0x31), b(0x58), b(0x53), b(0x4e), b(0x45), b(0x74), b(0x7f), b(0x62), b(0x69),
b(0xb0), b(0xbb), b(0xa6), b(0xad), b(0x9c), b(0x97), b(0x8a), b(0x81), b(0xe8), b(0xe3), b(0xfe), b(0xf5), b(0xc4), b(0xcf), b(0xd2), b(0xd9),
b(0x7b), b(0x70), b(0x6d), b(0x66), b(0x57), b(0x5c), b(0x41), b(0x4a), b(0x23), b(0x28), b(0x35), b(0x3e), b(0x0f), b(0x04), b(0x19), b(0x12),
b(0xcb), b(0xc0), b(0xdd), b(0xd6), b(0xe7), b(0xec), b(0xf1), b(0xfa), b(0x93), b(0x98), b(0x85), b(0x8e), b(0xbf), b(0xb4), b(0xa9), b(0xa2),
b(0xf6), b(0xfd), b(0xe0), b(0xeb), b(0xda), b(0xd1), b(0xcc), b(0xc7), b(0xae), b(0xa5), b(0xb8), b(0xb3), b(0x82), b(0x89), b(0x94), b(0x9f),
b(0x46), b(0x4d), b(0x50), b(0x5b), b(0x6a), b(0x61), b(0x7c), b(0x77), b(0x1e), b(0x15), b(0x08), b(0x03), b(0x32), b(0x39), b(0x24), b(0x2f),
b(0x8d), b(0x86), b(0x9b), b(0x90), b(0xa1), b(0xaa), b(0xb7), b(0xbc), b(0xd5), b(0xde), b(0xc3), b(0xc8), b(0xf9), b(0xf2), b(0xef), b(0xe4),
b(0x3d), b(0x36), b(0x2b), b(0x20), b(0x11), b(0x1a), b(0x07), b(0x0c), b(0x65), b(0x6e), b(0x73), b(0x78), b(0x49), b(0x42), b(0x5f), b(0x54),
b(0xf7), b(0xfc), b(0xe1), b(0xea), b(0xdb), b(0xd0), b(0xcd), b(0xc6), b(0xaf), b(0xa4), b(0xb9), b(0xb2), b(0x83), b(0x88), b(0x95), b(0x9e),
b(0x47), b(0x4c), b(0x51), b(0x5a), b(0x6b), b(0x60), b(0x7d), b(0x76), b(0x1f), b(0x14), b(0x09), b(0x02), b(0x33), b(0x38), b(0x25), b(0x2e),
b(0x8c), b(0x87), b(0x9a), b(0x91), b(0xa0), b(0xab), b(0xb6), b(0xbd), b(0xd4), b(0xdf), b(0xc2), b(0xc9), b(0xf8), b(0xf3), b(0xee), b(0xe5),
b(0x3c), b(0x37), b(0x2a), b(0x21), b(0x10), b(0x1b), b(0x06), b(0x0d), b(0x64), b(0x6f), b(0x72), b(0x79), b(0x48), b(0x43), b(0x5e), b(0x55),
b(0x01), b(0x0a), b(0x17), b(0x1c), b(0x2d), b(0x26), b(0x3b), b(0x30), b(0x59), b(0x52), b(0x4f), b(0x44), b(0x75), b(0x7e), b(0x63), b(0x68),
b(0xb1), b(0xba), b(0xa7), b(0xac), b(0x9d), b(0x96), b(0x8b), b(0x80), b(0xe9), b(0xe2), b(0xff), b(0xf4), b(0xc5), b(0xce), b(0xd3), b(0xd8),
b(0x7a), b(0x71), b(0x6c), b(0x67), b(0x56), b(0x5d), b(0x40), b(0x4b), b(0x22), b(0x29), b(0x34), b(0x3f), b(0x0e), b(0x05), b(0x18), b(0x13),
b(0xca), b(0xc1), b(0xdc), b(0xd7), b(0xe6), b(0xed), b(0xf0), b(0xfb), b(0x92), b(0x99), b(0x84), b(0x8f), b(0xbe), b(0xb5), b(0xa8), b(0xa3)};

    /**
     * This is used for multiplication by d (or 13) in the Galois field GF(256) such that TABLE_D[n] is equal to d * n.
     */
    private final static byte[] TABLE_D = new byte[] {
b(0x00), b(0x0d), b(0x1a), b(0x17), b(0x34), b(0x39), b(0x2e), b(0x23), b(0x68), b(0x65), b(0x72), b(0x7f), b(0x5c), b(0x51), b(0x46), b(0x4b),
b(0xd0), b(0xdd), b(0xca), b(0xc7), b(0xe4), b(0xe9), b(0xfe), b(0xf3), b(0xb8), b(0xb5), b(0xa2), b(0xaf), b(0x8c), b(0x81), b(0x96), b(0x9b),
b(0xbb), b(0xb6), b(0xa1), b(0xac), b(0x8f), b(0x82), b(0x95), b(0x98), b(0xd3), b(0xde), b(0xc9), b(0xc4), b(0xe7), b(0xea), b(0xfd), b(0xf0),
b(0x6b), b(0x66), b(0x71), b(0x7c), b(0x5f), b(0x52), b(0x45), b(0x48), b(0x03), b(0x0e), b(0x19), b(0x14), b(0x37), b(0x3a), b(0x2d), b(0x20),
b(0x6d), b(0x60), b(0x77), b(0x7a), b(0x59), b(0x54), b(0x43), b(0x4e), b(0x05), b(0x08), b(0x1f), b(0x12), b(0x31), b(0x3c), b(0x2b), b(0x26),
b(0xbd), b(0xb0), b(0xa7), b(0xaa), b(0x89), b(0x84), b(0x93), b(0x9e), b(0xd5), b(0xd8), b(0xcf), b(0xc2), b(0xe1), b(0xec), b(0xfb), b(0xf6),
b(0xd6), b(0xdb), b(0xcc), b(0xc1), b(0xe2), b(0xef), b(0xf8), b(0xf5), b(0xbe), b(0xb3), b(0xa4), b(0xa9), b(0x8a), b(0x87), b(0x90), b(0x9d),
b(0x06), b(0x0b), b(0x1c), b(0x11), b(0x32), b(0x3f), b(0x28), b(0x25), b(0x6e), b(0x63), b(0x74), b(0x79), b(0x5a), b(0x57), b(0x40), b(0x4d),
b(0xda), b(0xd7), b(0xc0), b(0xcd), b(0xee), b(0xe3), b(0xf4), b(0xf9), b(0xb2), b(0xbf), b(0xa8), b(0xa5), b(0x86), b(0x8b), b(0x9c), b(0x91),
b(0x0a), b(0x07), b(0x10), b(0x1d), b(0x3e), b(0x33), b(0x24), b(0x29), b(0x62), b(0x6f), b(0x78), b(0x75), b(0x56), b(0x5b), b(0x4c), b(0x41),
b(0x61), b(0x6c), b(0x7b), b(0x76), b(0x55), b(0x58), b(0x4f), b(0x42), b(0x09), b(0x04), b(0x13), b(0x1e), b(0x3d), b(0x30), b(0x27), b(0x2a),
b(0xb1), b(0xbc), b(0xab), b(0xa6), b(0x85), b(0x88), b(0x9f), b(0x92), b(0xd9), b(0xd4), b(0xc3), b(0xce), b(0xed), b(0xe0), b(0xf7), b(0xfa),
b(0xb7), b(0xba), b(0xad), b(0xa0), b(0x83), b(0x8e), b(0x99), b(0x94), b(0xdf), b(0xd2), b(0xc5), b(0xc8), b(0xeb), b(0xe6), b(0xf1), b(0xfc),
b(0x67), b(0x6a), b(0x7d), b(0x70), b(0x53), b(0x5e), b(0x49), b(0x44), b(0x0f), b(0x02), b(0x15), b(0x18), b(0x3b), b(0x36), b(0x21), b(0x2c),
b(0x0c), b(0x01), b(0x16), b(0x1b), b(0x38), b(0x35), b(0x22), b(0x2f), b(0x64), b(0x69), b(0x7e), b(0x73), b(0x50), b(0x5d), b(0x4a), b(0x47),
b(0xdc), b(0xd1), b(0xc6), b(0xcb), b(0xe8), b(0xe5), b(0xf2), b(0xff), b(0xb4), b(0xb9), b(0xae), b(0xa3), b(0x80), b(0x8d), b(0x9a), b(0x97)};

    /**
     * This is used for multiplication by e (or 14) in the Galois field GF(256) such that TABLE_E[n] is equal to e * n.
     */
    private final static byte[] TABLE_E = new byte[] {
b(0x00), b(0x0e), b(0x1c), b(0x12), b(0x38), b(0x36), b(0x24), b(0x2a), b(0x70), b(0x7e), b(0x6c), b(0x62), b(0x48), b(0x46), b(0x54), b(0x5a),
b(0xe0), b(0xee), b(0xfc), b(0xf2), b(0xd8), b(0xd6), b(0xc4), b(0xca), b(0x90), b(0x9e), b(0x8c), b(0x82), b(0xa8), b(0xa6), b(0xb4), b(0xba),
b(0xdb), b(0xd5), b(0xc7), b(0xc9), b(0xe3), b(0xed), b(0xff), b(0xf1), b(0xab), b(0xa5), b(0xb7), b(0xb9), b(0x93), b(0x9d), b(0x8f), b(0x81),
b(0x3b), b(0x35), b(0x27), b(0x29), b(0x03), b(0x0d), b(0x1f), b(0x11), b(0x4b), b(0x45), b(0x57), b(0x59), b(0x73), b(0x7d), b(0x6f), b(0x61),
b(0xad), b(0xa3), b(0xb1), b(0xbf), b(0x95), b(0x9b), b(0x89), b(0x87), b(0xdd), b(0xd3), b(0xc1), b(0xcf), b(0xe5), b(0xeb), b(0xf9), b(0xf7),
b(0x4d), b(0x43), b(0x51), b(0x5f), b(0x75), b(0x7b), b(0x69), b(0x67), b(0x3d), b(0x33), b(0x21), b(0x2f), b(0x05), b(0x0b), b(0x19), b(0x17),
b(0x76), b(0x78), b(0x6a), b(0x64), b(0x4e), b(0x40), b(0x52), b(0x5c), b(0x06), b(0x08), b(0x1a), b(0x14), b(0x3e), b(0x30), b(0x22), b(0x2c),
b(0x96), b(0x98), b(0x8a), b(0x84), b(0xae), b(0xa0), b(0xb2), b(0xbc), b(0xe6), b(0xe8), b(0xfa), b(0xf4), b(0xde), b(0xd0), b(0xc2), b(0xcc),
b(0x41), b(0x4f), b(0x5d), b(0x53), b(0x79), b(0x77), b(0x65), b(0x6b), b(0x31), b(0x3f), b(0x2d), b(0x23), b(0x09), b(0x07), b(0x15), b(0x1b),
b(0xa1), b(0xaf), b(0xbd), b(0xb3), b(0x99), b(0x97), b(0x85), b(0x8b), b(0xd1), b(0xdf), b(0xcd), b(0xc3), b(0xe9), b(0xe7), b(0xf5), b(0xfb),
b(0x9a), b(0x94), b(0x86), b(0x88), b(0xa2), b(0xac), b(0xbe), b(0xb0), b(0xea), b(0xe4), b(0xf6), b(0xf8), b(0xd2), b(0xdc), b(0xce), b(0xc0),
b(0x7a), b(0x74), b(0x66), b(0x68), b(0x42), b(0x4c), b(0x5e), b(0x50), b(0x0a), b(0x04), b(0x16), b(0x18), b(0x32), b(0x3c), b(0x2e), b(0x20),
b(0xec), b(0xe2), b(0xf0), b(0xfe), b(0xd4), b(0xda), b(0xc8), b(0xc6), b(0x9c), b(0x92), b(0x80), b(0x8e), b(0xa4), b(0xaa), b(0xb8), b(0xb6),
b(0x0c), b(0x02), b(0x10), b(0x1e), b(0x34), b(0x3a), b(0x28), b(0x26), b(0x7c), b(0x72), b(0x60), b(0x6e), b(0x44), b(0x4a), b(0x58), b(0x56),
b(0x37), b(0x39), b(0x2b), b(0x25), b(0x0f), b(0x01), b(0x13), b(0x1d), b(0x47), b(0x49), b(0x5b), b(0x55), b(0x7f), b(0x71), b(0x63), b(0x6d),
b(0xd7), b(0xd9), b(0xcb), b(0xc5), b(0xef), b(0xe1), b(0xf3), b(0xfd), b(0xa7), b(0xa9), b(0xbb), b(0xb5), b(0x9f), b(0x91), b(0x83), b(0x8d)};

    /**
     * This is a lookup table for the AES encryption. To find the new byte, the first 4 bits are used as the row index,
     * and the last 4 bits are used as the column index. For example, S(11011001) = SBOX[13][9] = 0x61 = 00110101
     */
    private final static byte[][] SBOX = new byte[][] {
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
    private final static byte[][] inverseSBOX = new byte[][] {
{b(0x52), b(0x09), b(0x6a), b(0xd5), b(0x30), b(0x36), b(0xa5), b(0x38), b(0xbf), b(0x40), b(0xa3), b(0x9e), b(0x81), b(0xf3), b(0xd7), b(0xfb)},
{b(0x7c), b(0xe3), b(0x39), b(0x82), b(0x9b), b(0x2f), b(0xff), b(0x87), b(0x34), b(0x8e), b(0x43), b(0x44), b(0xc4), b(0xde), b(0xe9), b(0xcb)},
{b(0x54), b(0x7b), b(0x94), b(0x32), b(0xa6), b(0xc2), b(0x23), b(0x3d), b(0xee), b(0x4c), b(0x95), b(0x0b), b(0x42), b(0xfa), b(0xc3), b(0x4e)},
{b(0x08), b(0x2e), b(0xa1), b(0x66), b(0x28), b(0xd9), b(0x24), b(0xb2), b(0x76), b(0x5b), b(0xa2), b(0x49), b(0x6d), b(0x8b), b(0xd1), b(0x25)},
{b(0x72), b(0xf8), b(0xf6), b(0x64), b(0x86), b(0x68), b(0x98), b(0x16), b(0xd4), b(0xa4), b(0x5c), b(0xcc), b(0x5d), b(0x65), b(0xb6), b(0x92)},
{b(0x6c), b(0x70), b(0x48), b(0x50), b(0xfd), b(0xed), b(0xb9), b(0xda), b(0x5e), b(0x15), b(0x46), b(0x57), b(0xa7), b(0x8d), b(0x9d), b(0x84)},
{b(0x90), b(0xd8), b(0xab), b(0x00), b(0x8c), b(0xbc), b(0xd3), b(0x0a), b(0xf7), b(0xe4), b(0x58), b(0x05), b(0xb8), b(0xb3), b(0x45), b(0x06)},
{b(0xd0), b(0x2c), b(0x1e), b(0x8f), b(0xca), b(0x3f), b(0x0f), b(0x02), b(0xc1), b(0xaf), b(0xbd), b(0x03), b(0x01), b(0x13), b(0x8a), b(0x6b)},
{b(0x3a), b(0x91), b(0x11), b(0x41), b(0x4f), b(0x67), b(0xdc), b(0xea), b(0x97), b(0xf2), b(0xcf), b(0xce), b(0xf0), b(0xb4), b(0xe6), b(0x73)},
{b(0x96), b(0xac), b(0x74), b(0x22), b(0xe7), b(0xad), b(0x35), b(0x85), b(0xe2), b(0xf9), b(0x37), b(0xe8), b(0x1c), b(0x75), b(0xdf), b(0x6e)},
{b(0x47), b(0xf1), b(0x1a), b(0x71), b(0x1d), b(0x29), b(0xc5), b(0x89), b(0x6f), b(0xb7), b(0x62), b(0x0e), b(0xaa), b(0x18), b(0xbe), b(0x1b)},
{b(0xfc), b(0x56), b(0x3e), b(0x4b), b(0xc6), b(0xd2), b(0x79), b(0x20), b(0x9a), b(0xdb), b(0xc0), b(0xfe), b(0x78), b(0xcd), b(0x5a), b(0xf4)},
{b(0x1f), b(0xdd), b(0xa8), b(0x33), b(0x88), b(0x07), b(0xc7), b(0x31), b(0xb1), b(0x12), b(0x10), b(0x59), b(0x27), b(0x80), b(0xec), b(0x5f)},
{b(0x60), b(0x51), b(0x7f), b(0xa9), b(0x19), b(0xb5), b(0x4a), b(0x0d), b(0x2d), b(0xe5), b(0x7a), b(0x9f), b(0x93), b(0xc9), b(0x9c), b(0xef)},
{b(0xa0), b(0xe0), b(0x3b), b(0x4d), b(0xae), b(0x2a), b(0xf5), b(0xb0), b(0xc8), b(0xeb), b(0xbb), b(0x3c), b(0x83), b(0x53), b(0x99), b(0x61)},
{b(0x17), b(0x2b), b(0x04), b(0x7e), b(0xba), b(0x77), b(0xd6), b(0x26), b(0xe1), b(0x69), b(0x14), b(0x63), b(0x55), b(0x21), b(0x0c), b(0x7d)}};


    /**
     * Converts an integer into a byte
     * @param b the integer we want to convert
     * @return the integer as a byte
     */
    private static byte b(int b) {
        return (byte) b;
    }

    /**
     * Encrypts a byte array using AES
     * @param plaintext the byte array we want to encrypt
     * @param key the key which must be 128 bits (16 bytes)
     * @return the encrypted byte array
     * @throws IllegalArgumentException if the key is not 128 bits (16 bytes)
     */
    public static byte[] encrypt(byte[] plaintext, byte[] key) throws IllegalArgumentException {
        if (key.length != 16)
            throw new IllegalArgumentException("Invalid key size. Must be 128 bits");



        // There is a block size of 128 bits or 16 bytes, so we need to pad until we have divisibility of 16
        byte[] paddedPlaintext = pad(plaintext, 16);
        byte[] cipher = new byte[paddedPlaintext.length];

        byte[][] blocks = makeBlock(paddedPlaintext, 16);

        byte[][] keySchedule = makeKeySchedule(key);

        // Now we need to go through each block of 16 bytes and encrypt
        for (int index = 0; index < blocks.length; index++) {

            // addRoundKey
            blocks[index] = xor(blocks[index], keySchedule[0]);

            for (int i = 1; i < 10; i++) {
                // subBytes
                blocks[index] = S(blocks[index]);
                // shiftRows
                blocks[index] = shiftRows(blocks[index]);
                // mixColumns
                blocks[index] = mixColumns(blocks[index]);
                // addRoundKey
                blocks[index] = xor(blocks[index], keySchedule[i]);
            }

            // subBytes
            blocks[index] = S(blocks[index]);
            // shiftRows
            blocks[index] = shiftRows(blocks[index]);
            // addRoundKey
            blocks[index] = xor(blocks[index], keySchedule[keySchedule.length - 1]);

            // Now we have the encrypted block, we will put it in the cipher in the correct spot
            for (int i = 0; i < 16; i++) {
                cipher[16 * index + i] = blocks[index][i];
            }
        }

        return cipher;
    }

    /**
     * Decrypts a byte array using AES
     * @param ciphertext the byte array we want to decrypt
     * @param key the key which must be 128 bits (16 bytes)
     * @return the decrypted String
     * @throws IllegalArgumentException if the key is not 128 bits (16 bytes) or if the ciphertext is not divisible by 16
     */
    public static String decrypt(byte[] ciphertext, byte[] key) throws IllegalArgumentException {
        if (key.length != 16)
            throw new IllegalArgumentException("Invalid key size. Must be 128, 192, or 256 bits");
        else if (ciphertext.length % 16 != 0)
            throw new IllegalArgumentException("Data has been lost");

        byte[] plaintext = new byte[ciphertext.length];
        byte[][] blocks = makeBlock(ciphertext, 16);

        byte[][] keySchedule = makeKeySchedule(key);

        for (int index = 0; index < blocks.length; index++) {
            // addRoundKey
            blocks[index] = xor(blocks[index], keySchedule[keySchedule.length - 1]);
            // invShiftRows
            blocks[index] = inverseShiftRows(blocks[index]);
            // invSubBytes
            blocks[index] = inverseS(blocks[index]);

            for (int i = 9; i >= 1; i--) {
                // addRoundKey
                blocks[index] = xor(blocks[index], keySchedule[i]);
                // invMixColumns
                blocks[index] = inverseMixColumns(blocks[index]);
                // invShiftRows
                blocks[index] = inverseShiftRows(blocks[index]);
                // invSubBytes
                blocks[index] = inverseS(blocks[index]);
            }

            // addRoundKey
            blocks[index] = xor(blocks[index], keySchedule[0]);

            // Now we have the plaintext block, we will put it in the plaintext in the correct spot
            for (int i = 0; i < 16; i++) {
                plaintext[16 * index + i] = blocks[index][i];
            }
        }

        // We have the plaintext now in bytes, but we need to strip it on the end of bytes we padded on
        plaintext = strip(plaintext);

        return byteArraytoString(plaintext);
    }

    /**
     * Encrypts a byte array using AES
     * @param plaintext the String we want to encrypt
     * @param key the String we want to encrypt with
     * @return the encrypted byte array
     */
    public static byte[] encrypt(String plaintext, String key) {
        return encrypt(stringToByteArray(plaintext), expandKey(key));
    }

    /**
     * Decrypts a byte array using AES
     * @param ciphertext the byte array we want to decrypt
     * @param key the String we want to decrypt with
     * @return the decrypted String
     */
    public static String decrypt(byte[] ciphertext, String key) {
        return decrypt(ciphertext, expandKey(key));
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
     * Combines the elements using a linear transformation, treating the 16 byte array as a 4x4 matrix. This corresponds
     * to the mixColumns step in AES.
     * @param bytes the bytes we want to combine
     * @return the mixed byte[]
     * @throws IllegalArgumentException if bytes does not have length 16
     */
    private static byte[] mixColumns(byte[] bytes) throws IllegalArgumentException {
        if (bytes.length != 16)
            throw new IllegalArgumentException("bytes must be length 16");

        // byte[] stores the values as signed bytes, but we need the unsigned values. We could use the Byte.toUnsignedInt
        // on each bytes[start] call we do, but this would be annoying to implement. So, we will convert these into values
        // beforehand
        int[] values = toUnsignedInt(bytes);

        byte[] result = new byte[16];

        // We need to perform the operation on each 4 groups of bytes
        for (int i = 0 ; i < 4; i++) {
            int start = i * 4;

            result[start] = b((TABLE_2[ values[start] ]) ^ (TABLE_3[ values[start + 1] ]) ^ values[start + 2] ^ values[start + 3]);
            result[start + 1] = b(values[start] ^ TABLE_2[ values[start + 1] ] ^ TABLE_3[ values[start + 2] ] ^ values[start + 3]);
            result[start + 2] = b(values[start] ^ values[start + 1] ^ TABLE_2[ values[start + 2] ] ^ TABLE_3[ values[start + 3] ]);
            result[start + 3] = b(TABLE_3[ values[start] ] ^ values[start + 1] ^ values[start + 2] ^ TABLE_2[ values[start + 3] ]);
        }

        return result;
    }

    /**
     * Combines the elements using a linear transformation, treating the 16 byte array as a 4x4 matrix. This corresponds
     * to the invMixColumns step in AES.
     * @param bytes the bytes we want to combine
     * @return the mixed byte[]
     * @throws IllegalArgumentException if bytes does not have length 16
     */
    private static byte[] inverseMixColumns(byte[] bytes) throws IllegalArgumentException {
        if (bytes.length != 16)
            throw new IllegalArgumentException("bytes must be length 16");

        // byte[] stores the values as signed bytes, but we need the unsigned values. We could use the Byte.toUnsignedInt
        // on each bytes[start] call we do, but this would be annoying to implement. So, we will convert these into values
        // beforehand
        int[] values = toUnsignedInt(bytes);

        byte[] result = new byte[16];

        // We need to perform the operation on each 4 groups of bytes
        for (int i = 0 ; i < 4; i++) {
            int start = i * 4;

            result[start] = b(TABLE_E[ values[start] ] ^ TABLE_B[ values[start + 1] ] ^ TABLE_D[ values[start + 2] ] ^ TABLE_9[ values[start + 3] ]);
            result[start + 1] = b(TABLE_9[ values[start] ] ^ TABLE_E[ values[start + 1] ] ^ TABLE_B[ values[start + 2] ] ^ TABLE_D[ values[start + 3] ]);
            result[start + 2] = b(TABLE_D[ values[start] ] ^ TABLE_9[ values[start + 1] ] ^ TABLE_E[ values[start + 2] ] ^ TABLE_B[ values[start + 3]]);
            result[start + 3] = b(TABLE_B[ values[start] ] ^ TABLE_D[ values[start + 1] ] ^ TABLE_9[ values[start + 2] ] ^ TABLE_E[ values[start + 3] ]);
        }

        return result;
    }

    /**
     * Moves the elements in a 16 length byte array according to the shiftRows step in AES. If we imagine the bytes as
     * a 4x4 matrix, the first row is unchanged, the second shifts to the left by one, the third shift to the left by
     * two, and the fourth shifts to the left by three.
     * @param bytes the bytes we want to shift around
     * @return the shifted byte array
     * @throws IllegalArgumentException if the byte[] is not length 16
     */
    private static byte[] shiftRows(byte[] bytes) throws IllegalArgumentException {
        if (bytes.length != 16)
            throw new IllegalArgumentException("bytes must be length 16");

        byte[] result = new byte[16];

        // Go column by row rotating up in each column accordingly (we shift the columns up instead of shifting the
        // rows left since we do not store the bytes as a matrix column-wise)
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                result[j * 4 + i] = bytes[Math.floorMod(j * 4 + i + (4 * i), 16)];
            }
        }

        return result;
    }

    /**
     * Moves the elements in a 16 length byte array according to the invShiftRows step in AES. If we imagine the bytes
     * as a 4x4 matrix, the first row is unchanged, the second shifts to the right by one, the third shift to the right
     * by two, and the fourth shifts to the right by three.
     * @param bytes the bytes we want to shift around
     * @return the shifted byte array
     * @throws IllegalArgumentException if the byte[] is not length 16
     */
    private static byte[] inverseShiftRows(byte[] bytes) throws IllegalArgumentException {
        if (bytes.length != 16)
            throw new IllegalArgumentException("bytes must be length 16");

        byte[] result = new byte[16];

        // Go column by row rotating up in each column accordingly (we shift the columns up instead of shifting the
        // rows left since we do not store the bytes as a matrix column-wise)
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                result[j * 4 + i] = bytes[Math.floorMod(j * 4 + i - (4 * i), 16)];
            }
        }

        return result;
    }

    /**
     * Xors two byte arrays together going index by index
     * @param byte1 the first byte we want to xor
     * @param byte2 the second byte we want to xor
     * @throws IllegalArgumentException if the two bytes have unequal length
     * @return the byte array achieved by xoring each byte
     */
    private static byte[] xor (byte[] byte1, byte[]byte2) {
        if (byte1.length != byte2.length)
            throw new IllegalArgumentException("byte1 has a different size than byte2");

        byte[] result = new byte[byte1.length];

        for (int i = 0; i < byte1.length; i++)
            result[i] = b(byte1[i] ^ byte2[i]);

        return result;
    }

    /**
     * Applies the Rijndael S-box to a byte
     * @param b the byte we want to work with
     * @return the output of the S-box
     */
    private static byte S(byte b) {
        int row = (b & 0xf0) >>> 4; // Gets the first 4 bits of the byte
        int col = b & 0x0f; // Gets the last 4 bits of the byte

        return SBOX[row][col];
    }

    /**
     * Applies the Rijndael S-box to a byte array
     * @param b the byte array we want to work with
     * @return the byte array output of the S-box
     */
    private static byte[] S(byte[] b) {
        byte[] result = new byte[b.length];

        for (int i = 0; i < result.length; i++)
            result[i] = S(b[i]);

        return result;
    }

    /**
     * Applies the inverse of the Rijndael S-box to a byte
     * @param b the byte we want to work with
     * @return the output of the inverse S-box
     */
    private static byte inverseS(byte b) {
        int row = (b & 0xf0) >>> 4; // Gets the first 4 bits of the byte
        int col = b & 0x0f; // Gets the last 4 bits of the byte

        return inverseSBOX[row][col];
    }

    /**
     * Applies the inverse Rijndael S-box to a byte array
     * @param b the byte array we want to work with
     * @return the byte array output of the inverse S-box
     */
    private static byte[] inverseS(byte[] b) {
        byte[] result = new byte[b.length];

        for (int i = 0; i < result.length; i++)
            result[i] = inverseS(b[i]);

        return result;
    }

    /**
     * Calls Byte.toUnsignedInt(byte) on each element in the bytes and returns the array of all the values
     * @param bytes the bytes we want the values of
     * @return an int[] of the unsigned values of bytes
     */
    private static int[] toUnsignedInt(byte[] bytes) {
        int[] result = new int[bytes.length];

        for (int i = 0; i < result.length; i++) {
            result[i] = Byte.toUnsignedInt(bytes[i]);
        }

        return result;
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
     * Strips a byte array that has previously been padded using the AES.pad() method in this class. This looks at the
     * last bits and removes them until all the padding has been gone. Note that this will acknowledge the last byte
     * as the padding byte and remove it until it finds the last bit is no longer a padding byte. This assumes that
     * each byte[] passed into pad() will receive some padding.
     * @param bytes the bytes we want to strip
     * @return the byte[] stripped of all padding
     */
    private static byte[] strip(byte[] bytes) {
        int endOfText = bytes.length - 1;

        // Find the end of the text where we placed the 10000000
        while (endOfText > 0 && bytes[endOfText] != b(0x80))
            endOfText--;

        byte[] stripped = new byte[endOfText];
        for (int i = 0; i < stripped.length; i++)
            stripped[i] = bytes[i];

        return stripped;
    }

    /**
     * Generates the round key schedule for AES. The number of rounds depends on the initialRoundKey length.
     * @param initialRoundKey the initial key which must be either 128 bits (16 bytes)
     * @return an array of byte arrays that is the key schedule for AES. Note that this will be 11 for AES-128
     * @throws IllegalArgumentException if the initial round key has a size that is not 128
     */
    private static byte[][] makeKeySchedule(byte[] initialRoundKey) {
        if (initialRoundKey.length != 16)
            throw new IllegalArgumentException("Key size must be 128 bits");

        // First we need to generate our round constants
        byte[][] roundConstants = new byte[11][4];

        // The zero index isn't necessary since it is defined as the initial key and so doesn't need a round constant
        roundConstants[0] = new byte[]{0x00, 0x00, 0x00, 0x00};

        // The first is defined as follows
        roundConstants[1] = new byte[]{0x01, 0x00, 0x00, 0x00};

        // The rest are defined recursively
        for (int i = 2; i < roundConstants.length; i++) {
            // Get the previous one
            byte previous = roundConstants[i - 1][0];
            // The new one will just be the previous one times 2
            byte newByte = b(2 * previous);

            // If the previous one is over 0x80 (128), multiplying times 2 spills over the byte limit, so xor with 0x11b
            if (Byte.toUnsignedInt(previous) >= 0x80)
                newByte ^= (byte) 0x11b;

            roundConstants[i] = new byte[]{newByte, 0x00, 0x00, 0x00};
        }


        // Now we can get to actually creating the key schedule
        byte[][] keySchedule = new byte[11][16];

        // The first round is just the initial key
        keySchedule[0] = initialRoundKey;

        for (int i = 1; i < keySchedule.length; i++) {
            // For each round we need to perform operations on the last 4 bytes of the previous round, and then derive
            // the other sets of 4 bytes

            byte[] lastBytes = new byte[4];

            for (int j = 0; j < 4; j++)
                // 12, 13, 14, 15 are the last four
                lastBytes[j] = keySchedule[i - 1][12 + j];

            // First we need to perform RotWord on the last 4 bytes, which shifts each byte down an index
            byte firstByte = lastBytes[0];
            for (int j = 0; j < 3; j++)
                lastBytes[j] = lastBytes[j + 1];
            lastBytes[3] = firstByte;

            // Then we use the S() function on each byte
            for (int j = 0; j < 4; j++)
                lastBytes[j] = S(lastBytes[j]);

            // Lastly we use our round constants
            for (int j = 0; j < 4; j++)
                lastBytes[j] ^= roundConstants[i][j];


            // Now to make the keySchedules we xor this byte we've made with the previous first set
            for (int j = 0; j < 4; j++)
                keySchedule[i][j] = b(keySchedule[i - 1][j] ^ lastBytes[j]);

            // For the rest of the bytes, we xor the previous key schedules in the same index, with the last index of
            // the key in the current round
            for (int j = 1; j < 4; j++) {

                for (int k = 0; k < 4; k++) {
                    keySchedule[i][j * 4 + k] = b(keySchedule[i][(j * 4 + k) - 4] ^ keySchedule[i - 1][j * 4 + k]);
                }
            }
        }

        return keySchedule;
    }

    /**
     * Expands a key to 128 bits using the MD5 hashing algorithm
     * @param key the String we want to expand
     * @return the expanded key
     */
    public static byte[] expandKey(String key) throws IllegalArgumentException {
        byte[] bytes = MD5.hash(key); // We will start just by hashing to get our string into bytes

        // These two calculated values will be used to determine the salt and amount of iterations
        // Note that for a specific key, these values will be the same each time it is ran, meaning the same expanded
        // key will be generated.
        int multipledASCIIs = 1;
        int summedASCIIs = 0;

        for (int i = 0; i < key.length(); i++) {
            multipledASCIIs *= key.charAt(i);
            summedASCIIs += key.charAt(i);
        }
        // We will hash this many times
        Random random = new Random(summedASCIIs);

        // 10,000 seems to be the max before a delay starts to be perceived
        int iterations = random.nextInt(10000);


        // We will add salt in each time before we hash to add an element of randomness
        random = new Random(multipledASCIIs);

        for (int i = 0; i < iterations; i++) {
            // For each iteration, we will add a certain amount of random bytes
            byte[] saltedBytes = Arrays.copyOf(bytes, 16 + random.nextInt(key.length()));

            for (int j = 16; j < saltedBytes.length; j++)
                saltedBytes[j] = b(random.nextInt());

            // Once we add the random bytes, we will hash to generate
            bytes = MD5.hash(saltedBytes);
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
     * Converts a given byte array to a String
     * @param input the byte array we want to convert
     * @return a String representation of the byte array
     */
    private static String byteArraytoString(byte[] input) {
        StringBuilder stringBuilder = new StringBuilder();

        for (byte b : input) {
            stringBuilder.append(Character.toString(b));
        }

        return stringBuilder.toString();
    }

}
