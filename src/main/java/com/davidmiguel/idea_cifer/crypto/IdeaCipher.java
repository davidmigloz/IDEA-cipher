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
            subKey = invertSubkey(tempSubKey);
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
            key[i] = (b1 | b2);                 // xxxxxxxxxxxxxxxx
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
     * Reverse and invert the subkeys to get the decryption subkeys.
     * They are either the additive or multiplicative inverses of the encryption subkeys in reverse order.
     *
     * @param subkey subkeys
     * @return inverted subkey
     */
    private static int[] invertSubkey(int[] subkey) {
        int[] invSubkey = new int[subkey.length];
        int p = 0;
        int i = ROUNDS * 6;
        // For the final output transformation (round 9)
        invSubkey[i + 0] = mulInv(subkey[p++]);     // 48 <- 0
        invSubkey[i + 1] = addInv(subkey[p++]);     // 49 <- 1
        invSubkey[i + 2] = addInv(subkey[p++]);     // 50 <- 2
        invSubkey[i + 3] = mulInv(subkey[p++]);     // 51 <- 3
        // From round 8 to 2
        for (int r = ROUNDS - 1; r > 0; r--) {
            i = r * 6;
            invSubkey[i + 4] = subkey[p++];         // 46 <- 4 ...
            invSubkey[i + 5] = subkey[p++];         // 47 <- 5 ...
            invSubkey[i + 0] = mulInv(subkey[p++]); // 42 <- 6 ...
            invSubkey[i + 2] = addInv(subkey[p++]); // 44 <- 7 ...
            invSubkey[i + 1] = addInv(subkey[p++]); // 43 <- 8 ...
            invSubkey[i + 3] = mulInv(subkey[p++]); // 45 <- 9 ...
        }
        // Round 1
        invSubkey[4] = subkey[p++];                 // 4 <- 46
        invSubkey[5] = subkey[p++];                 // 5 <- 47
        invSubkey[0] = mulInv(subkey[p++]);         // 0 <- 48
        invSubkey[1] = addInv(subkey[p++]);         // 1 <- 49
        invSubkey[2] = addInv(subkey[p++]);         // 2 <- 50
        invSubkey[3] = mulInv(subkey[p++]);         // 3 <- 51
        return invSubkey;
    }

    /**
     * Addition in the additive group (mod 2^16).
     * Range [0, 0xFFFF].
     */
    private static int add(int x, int y) {
        return (x + y) & 0xFFFF;
    }

    /**
     * Additive inverse in the additive group (mod 2^16).
     * Range [0, 0xFFFF].
     */
    private static int addInv(int x) {
        return (0x10000 - x) & 0xFFFF;
    }

    /**
     * Multiplication in the multiplicative group (mod 2^16+1 = mod 0x10001).
     * Range [0, 0xFFFF].
     */
    private static int mul(int x, int y) {
        long m = x * y;
        if (m != 0) {
            return (int) (m % 0x10001) & 0xFFFF;
        } else {
            if(x != 0 || y != 0){
                return (1 - x - y) & 0xFFFF;
            }
            return 0;
        }
    }

    /**
     * Multiplicative inverse in the multiplicative group (mod 2^16+1 = mod 0x10001).
     * It uses Extended Euclidean algorithm to compute the inverse.
     * For the purposes of IDEA, the all-zero sub-block is considered to represent 2^16 = −1
     * for multiplication modulo 216 + 1; thus the multiplicative inverse of 0 is 0.
     * Range [0, 0xFFFF].
     */
    private static int mulInv(int x) {
        if (x <= 1) {
            // 0 and 1 are their own inverses
            return x;
        }
        try {
            int y = 0x10001;
            int t0 = 1;
            int t1 = 0;
            while (true) {
                t1 += y / x * t0;
                y %= x;
                if (y == 1) {
                    return ( 1 - t1 ) & 0xffff;
                }
                t0 += x / y * t1;
                x %= y;
                if (x == 1) {
                    return t0;
                }
            }
        } catch (ArithmeticException e) {
            return 0;
        }
    }
}