package com.davidmiguel.idea_cifer.modes.algorithms;

import com.davidmiguel.idea_cifer.crypto.IdeaCipher;
import com.davidmiguel.idea_cifer.modes.OperationMode;

/**
 * OFB mode of operation.
 */
public class OFB extends OperationMode {

    protected OFB(IdeaCipher idea, boolean encrypt, int blockSize) {
        super(idea, encrypt);
    }

    @Override
    protected void crypt(byte[] data, int pos) {

    }
}
