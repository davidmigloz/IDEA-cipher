package com.davidmiguel.idea_cipher.crypto;

import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.Assert.*;

public class BlockCipherTest {
    @Test
    public void makeKey() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        String[] keys = {"asdf", "a", "@@@", "asdf+6556__", "654654654654654654654654654", ""};
        BlockCipher c = new IdeaCipher(keys[0], true);

        Method method = BlockCipher.class.getDeclaredMethod("makeKey", String.class);
        method.setAccessible(true);

        byte[] res = new byte[0];
        for (String key : keys) {
            try {
                res = (byte[]) method.invoke(c, key);
            } catch (Exception e) {
                System.out.println("Invalid key: " + key);
            }
            assertEquals("Wrong size", 16, res.length);
        }
    }
}