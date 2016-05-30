package com.davidmiguel.idea_cifer.crypto;

/**
 * BlockCipher.
 */
public abstract class BlockCipher {

    private int keySize;
    private int blockSize;

    public BlockCipher(int keySize, int blockSize) {
        this.keySize = keySize;
        this.blockSize = blockSize;
    }

    public int getKeySize() {
        return keySize;
    }

    public int getBlockSize() {
        return blockSize;
    }

    /**
     * Set the key from a block of bytes.
     */
    protected abstract void setKey(byte[] key);

    /**
     * Set the key from a string.
     *
     * @param keyStr string key
     */
    protected void setKey(String keyStr) {
        setKey(makeKey(keyStr));
    }

    /**
     * Turn a string into a key of the right length.
     */
    private byte[] makeKey(String keyStr) {
        byte[] key = new byte[keySize];
        int i, j;
        for (j = 0; j < key.length; ++j) {
            key[j] = 0;
        }
        for (i = 0, j = 0; i < keyStr.length(); i++, j = (j + 1) % key.length) {
            key[j] ^= (byte) keyStr.charAt(i);
        }
        return key;
    }

    /**
     * Encrypts / decrypts a 64-bit block of data.
     *
     * @param data   64-bit block of data
     * @param offset start point
     * @return 64-bit block of cipherdata
     */
    public abstract byte[] crypt(byte[] data, int offset);

    /**
     * Encrypts / decrypts a 64-bit block of data.
     *
     * @param data 64-bit block of data
     * @return 64-bit block of cipherdata
     */
    public byte[] crypt(byte[] data) {
        return crypt(data, 0);
    }
}
