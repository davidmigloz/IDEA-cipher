package com.davidmiguel.idea_cifer.modes.algorithms;

import com.davidmiguel.idea_cifer.crypto.IdeaCipher;
import com.davidmiguel.idea_cifer.modes.OperationMode;

/**
 * CBC mode of operation.
 */
public class CBC extends OperationMode {

    /** Data of the previous ciphertext block */
    byte[] prev;
    /** Data of the new ciphertext block */
    byte[] newPrev;

    public CBC(IdeaCipher idea, boolean encrypt) {
        super(idea, encrypt);
        prev = new byte[idea.getBlockSize()];
        newPrev = new byte[idea.getBlockSize()];
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        data = idea.crypt(data, pos);
    }
}
