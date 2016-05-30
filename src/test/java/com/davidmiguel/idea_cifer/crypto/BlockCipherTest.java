package com.davidmiguel.idea_cifer.crypto;

import org.junit.After;
import org.junit.Before;
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
        for (int i = 0; i < keys.length; i++) {
            try {
                res = (byte[]) method.invoke(c, keys[i]);
            }catch (Exception e) {
                System.out.println("Invalid key: " + keys[i]);
            }
            assertEquals("Wrong size", 16, res.length);
        }
    }
}