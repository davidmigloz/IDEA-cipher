package com.davidmiguel.idea_cifer.modes.algorithms;

import com.davidmiguel.idea_cifer.crypto.IdeaCipher;
import com.davidmiguel.idea_cifer.modes.OperationMode;

/**
 * ECB mode of operation.
 */
public class ECB extends OperationMode {

    public ECB(IdeaCipher idea, boolean encrypt) {
        super(idea, encrypt);
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        data = idea.crypt(data, pos);
    }
}
