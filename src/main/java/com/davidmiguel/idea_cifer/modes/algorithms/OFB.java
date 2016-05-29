package com.davidmiguel.idea_cifer.modes.algorithms;

import com.davidmiguel.idea_cifer.crypto.IdeaCipher;
import com.davidmiguel.idea_cifer.modes.OperationMode;

/**
 * Created by davidmigloz on 28/05/2016.
 */
public class OFB extends OperationMode {

    protected OFB(IdeaCipher idea, boolean encrypt, int blockSize) {
        super(idea, encrypt, blockSize);
    }

    @Override
    protected void crypt(byte[] data, int pos) {

    }
}
