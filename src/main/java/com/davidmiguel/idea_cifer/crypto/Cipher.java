package com.davidmiguel.idea_cifer.crypto;

/**
 * Created by davidmigloz on 28/05/2016.
 */
public abstract class Cipher {

    public int keySize;

    public Cipher(int keySize) {
        this.keySize = keySize;
    }
}
