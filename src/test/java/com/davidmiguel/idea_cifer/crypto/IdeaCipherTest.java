package com.davidmiguel.idea_cifer.crypto;

import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.Assert.*;

@SuppressWarnings("PrimitiveArrayArgumentToVarargsMethod")
public class IdeaCipherTest {
    @Test
    public void crypt() throws Exception {
        byte[] data = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] input = data.clone();
        String key = "asdfasdfasdfasdf";
        // Encrypt
        BlockCipher e = new IdeaCipher(key, true);
        e.crypt(input);
        // Decrypt
        BlockCipher d = new IdeaCipher(key, false);
        d.crypt(input);

        assertEquals("Different size", data.length, input.length);
        assertArrayEquals("Different data", data, input);
    }

    @Test
    public void generateSubkeys() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        byte[] userKey = {0,1,0,2,0,3,0,4,0,5,0,6,0,7,0,8};
        int[] eSubkey = {0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006,
                         0x0007, 0x0008, 0x0400, 0x0600, 0x0800, 0x0a00,
                         0x0c00, 0x0e00, 0x1000, 0x0200, 0x0010, 0x0014,
                         0x0018, 0x001c, 0x0020, 0x0004, 0x0008, 0x000c,
                         0x2800, 0x3000, 0x3800, 0x4000, 0x0800, 0x1000,
                         0x1800, 0x2000, 0x0070, 0x0080, 0x0010, 0x0020,
                         0x0030, 0x0040, 0x0050, 0x0060, 0x0000, 0x2000,
                         0x4000, 0x6000, 0x8000, 0xa000, 0xc000, 0xe001,
                         0x0080, 0x00c0, 0x0100, 0x0140};

        Method method = IdeaCipher.class.getDeclaredMethod("generateSubkeys", byte[].class);
        method.setAccessible(true);
        int[] subkey = (int[]) method.invoke(null, userKey);

        assertEquals("Different size", eSubkey.length, subkey.length);
        assertArrayEquals("Different subkeys", eSubkey, subkey);
    }

    @Test
    public void invertSubKey() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        byte[] userKey = {0,1,0,2,0,3,0,4,0,5,0,6,0,7,0,8};
        int[] eInvSubkey = {0xfe01, 0xff40, 0xff00, 0x659a, 0xc000, 0xe001,
                            0xfffd, 0x8000, 0xa000, 0xcccc, 0x0000, 0x2000,
                            0xa556, 0xffb0, 0xffc0, 0x52ab, 0x0010, 0x0020,
                            0x554b, 0xff90, 0xe000, 0xfe01, 0x0800, 0x1000,
                            0x332d, 0xc800, 0xd000, 0xfffd, 0x0008, 0x000c,
                            0x4aab, 0xffe0, 0xffe4, 0xc001, 0x0010, 0x0014,
                            0xaa96, 0xf000, 0xf200, 0xff81, 0x0800, 0x0a00,
                            0x4925, 0xfc00, 0xfff8, 0x552b, 0x0005, 0x0006,
                            0x0001, 0xfffe, 0xfffd, 0xc001,};

        Method method = IdeaCipher.class.getDeclaredMethod("generateSubkeys", byte[].class);
        method.setAccessible(true);
        int[] subkey = (int[]) method.invoke(null, userKey);

        method = IdeaCipher.class.getDeclaredMethod("invertSubkey", int[].class);
        method.setAccessible(true);
        int[] invSubkey = (int[]) method.invoke(null, subkey);

        assertEquals("Different size", eInvSubkey.length, invSubkey.length);
        assertArrayEquals("Different invSubkeys", eInvSubkey, invSubkey);
    }

    @Test
    public void add() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        int[] x = {0, 0, 100,   65536, 65536};
        int[] y = {0, 1, 100,   0,     1};
        int[] s = {0, 1, 200,   0,     1};

        Method method = IdeaCipher.class.getDeclaredMethod("add", int.class, int.class);
        method.setAccessible(true);

        for (int i = 0; i < x.length; i++) {
            int res = (int) method.invoke(null, x[i], y[i]);
            assertEquals("Incorrect sum", s[i], res);
        }
    }

    @Test
    public void addInv() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        int[] num = {0, 1,     100,   65535, 65536, 65537 };
        int[] inv = {0, 65535, 65436, 1,     0,     65535};

        Method method = IdeaCipher.class.getDeclaredMethod("addInv", int.class);
        method.setAccessible(true);

        for (int i = 0; i < num.length; i++) {
            int res = (int) method.invoke(null, num[i]);
            assertEquals("Incorrect inverse", inv[i], res);
        }
    }

    @Test
    public void mul() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        int[] x = {0, 0, 1, 100,   10000, 65535, 65536, 65537, 65538};
        int[] y = {0, 1, 0, 100,   10000, 1,     1,     1,     1};
        int[] m = {0, 0, 0, 10000, 56075, 65535, 0,     0,     1};

        Method method = IdeaCipher.class.getDeclaredMethod("mul", int.class, int.class);
        method.setAccessible(true);

        for (int i = 0; i < x.length; i++) {
            int res = (int) method.invoke(null, x[i], y[i]);
            assertEquals("Incorrect multiplication", m[i], res);
        }
    }

    @Test
    public void mulInv() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        int[] num = {0, 1, 100,   1000,  10000, 65536, 65537, 65538};
        int[] inv = {0, 1, 17695, 34538, 42776, 0,     0,     1};

        Method method = IdeaCipher.class.getDeclaredMethod("mulInv", int.class);
        method.setAccessible(true);

        for (int i = 0; i < num.length; i++) {
            int res = (int) method.invoke(null, num[i]);
            assertEquals("Incorrect inverse", inv[i], res);
        }
    }
}