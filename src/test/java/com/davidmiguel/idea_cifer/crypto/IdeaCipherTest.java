package com.davidmiguel.idea_cifer.crypto;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.Assert.*;

public class IdeaCipherTest {
    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() throws Exception {

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
                         0x0080, 0x00c0, 0x0100, 0x0140,};

        Method method = IdeaCipher.class.getDeclaredMethod("generateSubkeys", byte[].class);
        method.setAccessible(true);
        int[] subkey = (int[]) method.invoke(null, userKey);

        assertEquals("Different size", eSubkey.length, subkey.length);
        assertArrayEquals("Different subkeys", eSubkey, subkey);
    }
}