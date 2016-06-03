package com.davidmiguel.idea_cifer.modes;

import com.davidmiguel.idea_cifer.modes.algorithms.CBC;
import com.davidmiguel.idea_cifer.modes.algorithms.CFB;
import com.davidmiguel.idea_cifer.modes.algorithms.ECB;
import com.davidmiguel.idea_cifer.modes.algorithms.OFB;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/**
 * Encrypts or decrypts a files with different modes of operation.
 *
 * Based on http://www.source-code.biz/idea/java
 */
public class FileCipher {

    private static final Logger logger = LoggerFactory.getLogger(FileCipher.class);
    private static final int BLOCK_SIZE = 8;

    public static void cryptFile(String inputFileName, String outputFileName, String charKey,
                                 boolean encrypt, OperationMode.Mode mode) throws IOException {

        // Open input / output FileChannels
        try (FileChannel inChannel = FileChannel.open(Paths.get(inputFileName), StandardOpenOption.READ);
             FileChannel outChannel = FileChannel.open(Paths.get(outputFileName), StandardOpenOption.CREATE,
                     StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {

            // Select mode of operation
            OperationMode opMod;
            switch (mode) {
                case ECB:
                    opMod = new ECB(encrypt, charKey);
                    break;
                case CBC:
                    opMod = new CBC(encrypt, charKey);
                    break;
                case CFB:
                    opMod = new CFB(encrypt, charKey);
                    break;
                case OFB:
                    opMod = new OFB(charKey);
                    break;
                default:
                    throw new IllegalArgumentException("Incorrect mode of operation.");
            }
            logger.debug(encrypt ? "Encrypting..." : "Decrypting...");
            logger.debug("Mode: " + mode.toString());

            // Check and compute sizes of data
            long inFileSize = inChannel.size(); // Input file size (bytes)
            long inDataLen, outDataLen; // Input and output data size (bytes)
            if (encrypt) {
                inDataLen = inFileSize; // Input data size = input file size
                outDataLen = (inDataLen + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE; // Closest upper multiple of blockSize
                logger.debug("Sizes: " + inDataLen + "b input, " + (outDataLen + 8) + "b output");
            } else {
                if (inFileSize == 0) {
                    throw new IOException("Input file is empty.");
                } else if (inFileSize % BLOCK_SIZE != 0) {
                    throw new IOException("Input file size is not a multiple of " + BLOCK_SIZE + ".");
                }
                inDataLen = inFileSize - BLOCK_SIZE; // Last block is the data size (encrypted)
                outDataLen = inDataLen;
                logger.debug("Sizes: " + (inDataLen + 8) + "b input, <=" + outDataLen  + "b output");
            }

            // Encrypt / decrypt data
            processData(inChannel, inDataLen, outChannel, outDataLen, opMod);

            // Write / read lenght of the data
            if (encrypt) {
                // Add encrypted data length in an encrypted block at the end of the output file
                writeDataLength(outChannel, inDataLen, opMod);
            } else {
                // Read encrypted data length
                long dataSize = readDataLength(inChannel, opMod);
                // Check if it is coherent
                if (dataSize < 0 || dataSize > inDataLen || dataSize < inDataLen - BLOCK_SIZE + 1) {
                    throw new IOException("Input file is not a valid cryptogram.");
                }
                // Truncate output file to the leght of the data
                if (dataSize != outDataLen) {
                    outChannel.truncate(dataSize);
                    logger.debug("Truncate " + outDataLen + "b to " + dataSize + "b");
                }
            }
            outChannel.close();
        }
    }

    /**
     * Read the input file in chunks of 2MB, encrypt/decrypt the chunks and write it in the output file.
     */
    private static void processData(FileChannel inChannel, long inDataLen, FileChannel outChannel, long outDataLen,
                                    OperationMode opMod) throws IOException {
        final int bufSize = 0x200000; // 2MB of buffer
        ByteBuffer buf = ByteBuffer.allocate(bufSize);
        long filePos = 0;
        while (filePos < inDataLen) {
            // Read from input file into the buffer
            int bytesToRead = (int) Math.min(inDataLen - filePos, bufSize);
            buf.limit(bytesToRead);
            buf.position(0);
            int bytesRead = inChannel.read(buf);
            if (bytesRead != bytesToRead) {
                throw new IOException("Incomplete data chunk read from file.");
            }
            // Encrypt chunk
            int chunkLen = (bytesRead + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE; // Closest upper multiple of blockSize
            Arrays.fill(buf.array(), bytesRead, chunkLen, (byte) 0); // Fill the free space of the chunk with 0
            for (int pos = 0; pos < chunkLen; pos += BLOCK_SIZE) {
                opMod.crypt(buf.array(), pos); // Encrypt chunk with chosen operation mode
            }
            // Write buffer to output file
            int bytesToWrite = (int) Math.min(outDataLen - filePos, chunkLen);
            buf.limit(bytesToWrite);
            buf.position(0);
            int bytesWritten = outChannel.write(buf);
            if (bytesWritten != bytesToWrite) {
                throw new IOException("Incomplete data chunk written to file.");
            }
            filePos += chunkLen;
        }
    }

    /**
     * Write the length of the encrypted data in an encrypted block at the end of the file.
     * The length is package is a 8-byte block, this block is encrypted and finally added at the end
     * of output file.
     */
    private static void writeDataLength(FileChannel outChannel, long dataLength, OperationMode opMod)
            throws IOException {
        // Package the dataLength into an 8-byte block
        byte[] block = packDataLength(dataLength);
        // Encrypt block
        opMod.crypt(block);
        // Write block at the end of the file
        ByteBuffer buf = ByteBuffer.wrap(block);
        int bytesWritten = outChannel.write(buf);
        if (bytesWritten != BLOCK_SIZE) {
            throw new IOException("Error while writing data length suffix.");
        }
    }

    /**
     * Get the length of the data that was encrypted.
     * This data is saved encrypted in the last block of the cryptogram.
     * Read the last block of the file, decrypt block and unpackage data lenght.
     */
    private static long readDataLength(FileChannel channel, OperationMode opMod) throws IOException {
        // Get last block
        ByteBuffer buf = ByteBuffer.allocate(BLOCK_SIZE);
        int bytesRead = channel.read(buf);
        if (bytesRead != BLOCK_SIZE) {
            throw new IOException("Unable to read data length suffix.");
        }
        byte[] block = buf.array();
        // Decrypt block
        opMod.crypt(block);
        // Unpackage data length
        return unpackDataLength(block);
    }

    /**
     * Packs 45-bit number into an 8-byte block. Used to encode the file size.
     */
    private static byte[] packDataLength(long size) {
        if (size > 0x1FFFFFFFFFFFL) { // 45 bits -> 32TB
            throw new IllegalArgumentException("File too long.");
        }
        byte[] b = new byte[BLOCK_SIZE];
        b[7] = (byte) (size << 3);
        b[6] = (byte) (size >> 5);
        b[5] = (byte) (size >> 13);
        b[4] = (byte) (size >> 21);
        b[3] = (byte) (size >> 29);
        b[2] = (byte) (size >> 37);
        return b;
    }

    /**
     * Extracts a 45-bit number from an 8-byte block. Used to decode the file size.
     * Returns -1 if the encoded value is invalid. This means that the input file is not a valid cryptogram.
     */
    private static long unpackDataLength(byte[] b) {
        if (b[0] != 0 || b[1] != 0 || (b[7] & 7) != 0) {
            return -1;
        }
        return (long) (b[7] & 0xFF) >> 3 |
                (long) (b[6] & 0xFF) << 5 |
                (long) (b[5] & 0xFF) << 13 |
                (long) (b[4] & 0xFF) << 21 |
                (long) (b[3] & 0xFF) << 29 |
                (long) (b[2] & 0xFF) << 37;
    }
}
