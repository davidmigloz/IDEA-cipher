package com.davidmiguel.idea_cipher.modes.algorithms;

import com.davidmiguel.idea_cipher.crypto.CrytoUtils;
import com.davidmiguel.idea_cipher.crypto.IdeaCipher;
import com.davidmiguel.idea_cipher.modes.OperationMode;

import java.util.Arrays;

/**
 * CFB mode of operation.
 * Each ciphertext block gets "fed back" into the encryption process in order to encrypt the next plaintext block.
 * r = 8 bytes
 */
public class CFB extends OperationMode {

    private static final int R = 8;

    private int blockSize;
    private int partSize;
    private int rounds;
    private byte[] feedback;

    public CFB(boolean encrypt, String key) {
        super(new IdeaCipher(key, true), encrypt);
        blockSize = idea.getBlockSize();
        assert blockSize % R == 0 : "R must be divisor of blockSize";
        partSize = R;
        rounds = blockSize / R;
        feedback = CrytoUtils.makeKey(key, blockSize); // Get initial vector (IV) from user key
    }

    @Override
    protected void crypt(byte[] data, int pos) {
        // Divide de block of data of size blockSize to partSize blocks
        byte[][] block = new byte[rounds][];
        for (int i = 0; i < rounds; i++) {
            block[i] = Arrays.copyOfRange(data, pos + partSize * i, pos + partSize * i + partSize);
        }
        // If decyphering -> save cryptogram (needed in xor operation)
        byte[][] crypt = new byte[0][];
        if (!this.isEncrypt()) {
            crypt = new byte[rounds][];
            for (int i = 0; i < rounds; i++) {
                crypt[i] = block[i].clone();
            }
        }
        // Run CFB algorithm
        byte[] feedbackP1, feedbackP2;
        for (int i = 0; i < rounds; i++) {
            idea.crypt(feedback);                                           // Encrypt feedback
            feedbackP1 = Arrays.copyOfRange(feedback, 0, partSize);         // Leftmost R-Bytes of feedback
            feedbackP2 = Arrays.copyOfRange(feedback, partSize, blockSize); // Rightmost (blockSize-R)-Bytes of feedback
            CrytoUtils.xor(block[i], 0, feedbackP1, partSize);              // XOR part of data and feecback
            if (this.isEncrypt()) {
                feedback = CrytoUtils.concat2Bytes(feedbackP2, block[i]);   // Update feedback with the new cipherblock
            } else {
                feedback = CrytoUtils.concat2Bytes(feedbackP2, crypt[i]);   // Update feedback with the cipherblock saved
            }
        }
        // Merge results
        for (int i = 0; i < rounds; i++) {
            System.arraycopy(block[i], 0, data, pos + partSize * i, partSize);
        }
    }
}