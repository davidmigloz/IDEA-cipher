package com.davidmiguel.idea_cipher.modes;

import com.davidmiguel.idea_cipher.MainApp;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class FileCipherTest {

    @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
    @Test
    public void cryptFile() throws Exception {
        String key           = "6FY0@7j@N'f4UQy9Bv\",+D)g@>QRRQ";
        String resourcesPath = "src/test/resources/test-files/";
        String fileExt       = ".txt";
        String cryptExt      = ".cif";
        String decryptExt    = ".dec";

        // Files of given size to test
        String[] files = new String[10];
        files[0] = generateFile(resourcesPath, 0);          // 0B
        files[1] = generateFile(resourcesPath, 1);          // 1B
        files[2] = generateFile(resourcesPath, 7);          // 7B
        files[3] = generateFile(resourcesPath, 8);          // 8B (blockSize)
        files[4] = generateFile(resourcesPath, 9);          // 9KB
        files[5] = generateFile(resourcesPath, 15);         // 15MB
        files[6] = generateFile(resourcesPath, 16);         // 16B (keySize)
        files[7] = generateFile(resourcesPath, 17);         // 17B
        files[8] = generateFile(resourcesPath, 1024);       // 1KB
        files[9] = generateFile(resourcesPath, 1048576);    // 1MB

        // Start UI
        new Thread(() -> MainApp.main(null)).start();

        // Method to test
        Method method = FileCipher.class.getDeclaredMethod("cryptFile");
        method.setAccessible(true);

        for(String file : files){
            // For each file test the 4 modes of operation
            for (OperationMode.Mode mode : OperationMode.Mode.values()) {
                // Encrypt
                FileCipher encryptTask = new FileCipher(resourcesPath + file + fileExt,
                        resourcesPath + file + cryptExt,
                        key, true, mode);
                method.invoke(encryptTask);
                // Decrypt
                FileCipher decryptTask = new FileCipher(resourcesPath + file + cryptExt,
                        resourcesPath + file + decryptExt,
                        key, false, mode);
                method.invoke(decryptTask);
                // Check
                File file1 = new File(resourcesPath + file + fileExt);
                File file2 = new File(resourcesPath + file + decryptExt);
                assertTrue("Different files", FileUtils.contentEquals(file1, file2));
            }
        }
    }

    /**
     * Generate files of given size.
     *
     * @param path destination path
     * @param bytes size of the file to generate (in bytes)
     * @return name of the file (without extension)
     */
    private static String generateFile(String path, int bytes) throws IOException {
        String name = bytes + "bytes";
        Path file = Paths.get(path + name + ".txt");
        if(!Files.exists(file)){
            // Generate content
            List<String> data = new ArrayList<>(1);
            data.add(generateContent(bytes));
            Files.write(file, data, Charset.forName("UTF-8"));
        }
        return name;
    }

    /**
     * Generate a string of given size.
     *
     * @param bytes size of the string (in bytes)
     * @return string of bytes size
     */
    private static String generateContent(int bytes){
        String s = "";
        if (bytes > 0) {
            char[] array = new char[bytes];
            Arrays.fill(array, '0');
            s = new String(array);
        }
        return s;
    }
}