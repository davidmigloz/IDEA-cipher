package com.davidmiguel.idea_cifer.modes;

import com.davidmiguel.idea_cifer.crypto.IdeaCipher;

/**
 * Created by davidmigloz on 28/05/2016.
 */
public abstract class OperationMode {

    /** Idea cipher */
    IdeaCipher idea;
    /** Encrypt / Decrypt */
    boolean encrypt;
    /** Data of the previous ciphertext block */
    byte[] prev;
    /** Data of the new ciphertext block */
    byte[] newPrev;

    protected OperationMode(IdeaCipher idea, boolean encrypt, int blockSize) {
        this.idea = idea;
        this.encrypt = encrypt;
        prev = new byte[blockSize];
        newPrev = new byte[blockSize];
    }

    protected abstract void crypt(byte[] data, int pos);
}
