package com.davidmiguel.idea_cipher.modes.algorithms;

import com.davidmiguel.idea_cipher.crypto.CrytoUtils;
import com.davidmiguel.idea_cipher.crypto.IdeaCipher;
import com.davidmiguel.idea_cipher.modes.OperationMode;

/**
 * OFB mode of operation.
 * It generates keystream blocks, which are then XORed with the plaintext blocks to get the ciphertext.
 * ISO 10116: requires an n-bit feedback -> more secure.
 */
public class OFB extends OperationMode {

    private int blockSize;
    private byte[] feedback;

    public OFB(String key) {
        super(new IdeaCipher(key, true), true);
        blockSize = idea.getBlockSize();
        feedback = CrytoUtils.makeKey(key, blockSize); // Get initial vector (IV) from user key
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        idea.crypt(feedback);                           // Encrypt feedback
        CrytoUtils.xor(data, pos, feedback, blockSize); // XOR data and feecback
    }
}