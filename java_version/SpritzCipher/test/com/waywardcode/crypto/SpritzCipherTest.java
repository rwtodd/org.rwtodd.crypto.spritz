/*
 * Copyright Richard Todd. I put the code under the
 * GPL v2.0.  See the LICENSE file in the repository.
 * for more information.
 */
package com.waywardcode.crypto;

import java.util.Arrays;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author richa
 */
public class SpritzCipherTest {
    
    public SpritzCipherTest() {
    }
    
//    @BeforeClass
//    public static void setUpClass() {
//    }
//    
//    @AfterClass
//    public static void tearDownClass() {
//    }
//    
//    @Before
//    public void setUp() {
//    }
//    
//    @After
//    public void tearDown() {
//    }

    
    /**
     * Test that hashes on channels come out the same an arrays...
     * @throws java.io.IOException
     */
    @Test
    public void testHashTypes() throws java.io.IOException {
        byte[] orig = "Here is an example text".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] arrHash = SpritzCipher.hash(256, orig);
        
        java.io.InputStream  origStream = new java.io.ByteArrayInputStream(orig);
        byte[] isHash = SpritzCipher.hash(256, origStream);
               
        Assert.assertArrayEquals(arrHash, isHash);
    }
    
    /**
     * Test of SpritzCipher hash.
     */
    @Test
    public void testHashes() {
        System.out.println("Test against known-correct hashes.");
        byte[] answer = SpritzCipher.hash(256, "ABC".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        Assert.assertArrayEquals(new byte[]{(byte)0x02, (byte)0x8f, (byte)0xa2, (byte)0xb4, 
                                            (byte)0x8b, (byte)0x93, (byte)0x4a, (byte)0x18}, 
                                 Arrays.copyOfRange(answer, 0, 8));
        
        answer = SpritzCipher.hash(256, "spam".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        Assert.assertArrayEquals(new byte[]{(byte)0xac, (byte)0xbb, (byte)0xa0, (byte)0x81, 
                                            (byte)0x3f, (byte)0x30, (byte)0x0d, (byte)0x3a}, 
                                 Arrays.copyOfRange(answer, 0, 8));
        
        answer = SpritzCipher.hash(256, "arcfour".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        Assert.assertArrayEquals(new byte[]{(byte)0xff, (byte)0x8c, (byte)0xf2, (byte)0x68, 
                                            (byte)0x09, (byte)0x4c, (byte)0x87, (byte)0xb9}, 
                                 Arrays.copyOfRange(answer, 0, 8));

    }

    
}
