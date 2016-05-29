package com.davidmiguel.idea_cifer.crypto;

/**
 * Implementation of IDEA symmetric-key block cipher.
 */
public class IdeaCipher extends BlockCipher {

    private static final int ROUNDS = 8;

    private boolean encrypt;
    private int[] subKey;


    public IdeaCipher(String keyStr, boolean encrypt) {
        super(16, 8);
        this.encrypt = encrypt;
        setKey(keyStr);
    }

    public IdeaCipher(byte[] key, boolean encrypt) {
        super(16, 8);
        setKey(key);
    }

    @Override
    protected void setKey(byte[] key) {
        int[] tempSubKey = generateSubkeys(key);
        if (encrypt) {
            subKey = tempSubKey;
        } else {
            //subKey = invertSubKey(tempSubKey);
        }
    }

    /**
     * Creating the subkeys from the user key.
     *
     * @param userKey 128-bit user key
     * @return 52 16-bit key sub-blocks (six for each of the eight rounds and four more for the output transformation)
     */
    private static int[] generateSubkeys(byte[] userKey) {
        if (userKey.length != 16) {
            throw new IllegalArgumentException();
        }
        int[] key = new int[ROUNDS * 6 + 4]; // 52 16-bit subkeys

        // The 128-bit userKey is divided into eight 16-bit subkeys
        int b1, b2;
        for (int i = 0; i < userKey.length / 2; i++) {
            b1 = (userKey[2 * i] & 0xFF) << 8;  // xxxxxxxx00000000
            b2 = userKey[2 * i + 1] & 0xFF;     // 00000000xxxxxxxx
            key[i] = (b1 | b2);         // xxxxxxxxxxxxxxxx
        }

        // The key is rotated 25 bits to the left and again divided into eight subkeys.
        // The first four are used in round 2; the last four are used in round 3.
        // The key is rotated another 25 bits to the left for the next eight subkeys, and so on.
        for (int i = userKey.length / 2; i < key.length; i++) {
            // It starts combining k1 shifted 9 bits with k2. This is 16 bits of k0 + 9 bits shifted from k1 = 25 bits
            b1 = key[(i + 1) % 8 != 0 ? i - 7 : i - 15] << 9;   // k1,k2,k3...k6,k7,k0,k9, k10...k14,k15,k8,k17,k18...
            b2 = key[(i + 2) % 8 < 2 ? i - 14 : i - 6] >> 7;    // k2,k3,k4...k7,k0,k1,k10,k11...k15,k8, k9,k18,k19...
            key[i] = (b1 | b2) & 0xFFFF;
        }
        return key;
    }

    /**
     * Reverse and invert the sub-keys.
     *
     * @param subkey
     * @return
     */
    private int[] invertSubKey(int[] subkey) {

        return null;
    }
}
