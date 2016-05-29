package com.davidmiguel.idea_cifer.crypto;

/**
 * Created by davidmigloz on 28/05/2016.
 */
public abstract class BlockCipher extends Cipher {

    private int blockSize;

    public BlockCipher(int keySize, int blockSize) {
        super(keySize);
        this.blockSize = blockSize;
    }

    public int getBlockSize() {
        return blockSize;
    }

    /**
     * Encrypt a block of bytes.
     */
    public abstract void encrypt(byte[] clearText, int clearOff, byte[] cipherText, int cipherOff);

    /*
     * Decrypt a block of bytes.
     */
    public abstract void decrypt(byte[] cipherText, int cipherOff, byte[] clearText, int clearOff);

    /**
     * Encrypt a block of bytes.
     */
    public void encrypt(byte[] clearText, byte[] cipherText) {
        encrypt(clearText, 0, cipherText, 0);
    }

    /**
     * Decrypt a block of bytes.
     */
    public void decrypt(byte[] cipherText, byte[] clearText) {
        decrypt(cipherText, 0, clearText, 0);
    }
}
