package com.davidmiguel.idea_cifer.modes.algorithms;

import com.davidmiguel.idea_cifer.crypto.CrytoUtils;
import com.davidmiguel.idea_cifer.crypto.IdeaCipher;
import com.davidmiguel.idea_cifer.modes.OperationMode;

/**
 * CBC mode of operation.
 * Each block of plaintext is XORed with the previous ciphertext block before being encrypted.
 * This way, each ciphertext block depends on all plaintext blocks processed up to that point.
 * To make each message unique, a initial vector generated from the user key is used.
 */
public class CBC extends OperationMode {

    private int blockSize;
    private byte[] prev;
    private byte[] newPrev;

    public CBC(IdeaCipher idea, boolean encrypt, String key) {
        super(idea, encrypt);
        blockSize = idea.getBlockSize();
        prev = CrytoUtils.makeKey(key, blockSize); // Get initial vector (IV) from user key
        newPrev = new byte[blockSize];
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        if (encrypt) {
            CrytoUtils.xor(data, pos, prev, blockSize);         // XOR block with previous encrypted block
            idea.crypt(data, pos);                              // Encrypt block
            System.arraycopy(data, pos, prev, 0, blockSize);    // Save encrypted block for next time
        } else {
            System.arraycopy(data, pos, newPrev, 0, blockSize); // Save encrypted block for next time
            idea.crypt(data, pos);                              // Decrypt block
            CrytoUtils.xor(data, pos, prev, blockSize);         // XOR block with previous encrypted block
            prev = newPrev.clone();                             // Update prev block
        }
    }
}
