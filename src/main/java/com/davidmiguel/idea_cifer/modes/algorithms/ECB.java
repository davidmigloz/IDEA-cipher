package com.davidmiguel.idea_cifer.modes.algorithms;

import com.davidmiguel.idea_cifer.crypto.IdeaCipher;
import com.davidmiguel.idea_cifer.modes.OperationMode;


/**
 * ECB mode of operation.
 * The message is divided into blocks, and each block is encrypted separately.
 */
public class ECB extends OperationMode {

    public ECB(IdeaCipher idea, boolean encrypt) {
        super(idea, encrypt);
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        idea.crypt(data, pos); // Encrypt / decrypt block
    }
}
