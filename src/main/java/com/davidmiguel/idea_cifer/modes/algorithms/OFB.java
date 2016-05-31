package com.davidmiguel.idea_cifer.modes.algorithms;

import com.davidmiguel.idea_cifer.crypto.CrytoUtils;
import com.davidmiguel.idea_cifer.crypto.IdeaCipher;
import com.davidmiguel.idea_cifer.modes.OperationMode;

/**
 * OFB mode of operation.
 */
public class OFB extends OperationMode {

    private int blockSize;
    private byte[] feedback;

    public OFB(IdeaCipher idea, boolean encrypt, String key) {
        super(idea, encrypt);
        blockSize = idea.getBlockSize();
        feedback = CrytoUtils.makeKey(key, blockSize); // Get initial vector (IV) from user key
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        if (encrypt) {

        } else {

        }
    }
}
