package com.davidmiguel.idea_cifer.modes;

import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.*;

public class FileCipherTest {

    private static final Logger logger = LoggerFactory.getLogger(FileCipherTest.class);

    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() throws Exception {

    }

    @Test
    public void cryptFile() throws Exception {
        String key = "asdfasdfasdf";
        String resourcesPath  = "src/test/resources/";
        String fileName       = "text.txt";
        String cryptogramName = "text.cif";
        String newFileName    = "text.dec";

        FileCipher.cryptFile(resourcesPath + fileName, resourcesPath + cryptogramName,
                key, true, OperationMode.Mode.CBC);
        logger.debug(">>----------------");
        FileCipher.cryptFile(resourcesPath + cryptogramName, resourcesPath + newFileName,
                key, false, OperationMode.Mode.CBC);

        File file1 = new File(resourcesPath + fileName);
        File file2 = new File(resourcesPath + newFileName);
        assertTrue("Different files", FileUtils.contentEquals(file1, file2));
    }

}