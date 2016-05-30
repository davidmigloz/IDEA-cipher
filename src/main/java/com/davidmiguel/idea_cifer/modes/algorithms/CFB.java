package com.davidmiguel.idea_cifer.modes.algorithms;

import com.davidmiguel.idea_cifer.crypto.IdeaCipher;
import com.davidmiguel.idea_cifer.modes.OperationMode;

/**
 * CFB mode of operation.
 */
public class CFB extends OperationMode {

    public CFB(IdeaCipher idea, boolean encrypt) {
        super(idea, encrypt);
    }

    @Override
    protected void crypt(byte[] data, int pos) {

    }
}
