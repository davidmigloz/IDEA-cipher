package com.davidmiguel.idea_cifer.crypto;

/**
 * Created by davidmigloz on 28/05/2016.
 */
public abstract class Cipher {

    private int keySize;

    public Cipher(int keySize) {
        this.keySize = keySize;
    }

    public int getKeySize() {
        return keySize;
    }

    /**
     * Set the key from a block of bytes.
     */
    public abstract void setKey(byte[] key);

    /**
     * Set the key from a string.
     */
    public void setKey(String keyStr) {
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
}
