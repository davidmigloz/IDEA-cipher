package com.davidmiguel.idea_cifer.crypto;

public class CrytoUtils {
    /**
     * Turn a string into a key of the given length.
     */
    public static byte[] makeKey(String charKey, int size) {
        byte[] key = new byte[size];
        int i, j;
        for (j = 0; j < key.length; ++j) {
            key[j] = 0;
        }
        for (i = 0, j = 0; i < charKey.length(); i++, j = (j + 1) % key.length) {
            key[j] ^= (byte) charKey.charAt(i);
        }
        return key;
    }

    /**
     * XOR two blocks.
     * @param a block 1
     * @param pos offset in block 1
     * @param b block 2
     * @param blockSize size of the block to xor
     */
    public static void xor(byte[] a, int pos, byte[] b, int blockSize) {
        for (int p = 0; p < blockSize; p++) {
            a[pos + p] ^= b[p];
        }
    }
}
