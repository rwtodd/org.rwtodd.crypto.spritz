/*
 * Copyright Richard Todd. I put the code under the
 * GPL v2.0.  See the LICENSE file in the repository.
 * for more information.
 */
package com.waywardcode.crypto;

import static com.waywardcode.crypto.SpritzUtils.*;
import java.io.OutputStream;
import java.io.InputStream;
import java.util.Random;
import java.io.IOException;
import java.util.Arrays;

/**
 * A class to encapsulate the header of a Spritz-encrypted 
 * file.  It can read and write a header, and for password-changing
 * purposes, it does both.
 * @author richard
 */
public class SpritzHeader {
    private final Random rnd;
    
    public int getHeaderSize() { return 12+64; }
    
    private byte[] IV;
    public byte[] getIV() { 
        if(IV == null) { 
            IV = new byte[4];
            rnd.nextBytes(IV);
        }
        return IV; 
    }
    public void setIV(byte[] iv) { if(iv == null) { IV = iv; } else { IV = Arrays.copyOf(iv,4); } }
    
    private byte[] payloadKey;
    public byte[] getPayloadKey() { 
        if(payloadKey == null) { 
            payloadKey = new byte[64];
            rnd.nextBytes(payloadKey);
        }
        return payloadKey; 
    }
    public void setPayloadKey(byte[] plk) { payloadKey = Arrays.copyOf(plk, 64); }
        
    public SpritzHeader() {
        rnd = new java.util.Random(System.currentTimeMillis());
        IV = null;
        payloadKey = null;
    }
    
    public void Read(InputStream in, String password) throws IOException {
        IV = new byte[4];
        if (readFully(in, IV) != 4) {
            throw new IllegalArgumentException("Instream wasn't even long enough to contain an header!");
        }

        XORInto(IV, SpritzCipher.hash(32, password.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        SpritzCipher cipher = SpritzCipher.cipherStream(password, Arrays.copyOf(IV,4));

        /* now decrypt the rest of the header */
        byte[] header = new byte[72];
        if (readFully(in, header) != 72) {
            throw new IllegalArgumentException("Instream wasn't even long enough to contain an header!");
        }
        cipher.squeezeXOR(header, 0, 4);
        cipher.skip(header[3]&0xFF);
        cipher.squeezeXOR(header, 4, 68);

        // now verify the random bytes and their hash...
        final byte[] randomBytes = Arrays.copyOfRange(header, 0, 4);
        final byte[] randomHash = Arrays.copyOfRange(header, 4, 8);
        final byte[] testHash = SpritzCipher.hash(32, randomBytes);
        if (!java.util.Arrays.equals(testHash, randomHash)) {
            throw new IllegalStateException("Bad Password or corrupted file!");
        }

        payloadKey = Arrays.copyOfRange(header, 8, 72);
    }

    public void Write(OutputStream out, String password) throws IOException {

        // first, write the encrypted iv...
        final byte[] encIV = Arrays.copyOf(getIV(), 4);
        XORInto(encIV, SpritzCipher.hash(32, password.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        out.write(encIV);

        SpritzCipher cipher = SpritzCipher.cipherStream(password, Arrays.copyOf(IV,4));

        // now, write 4 random bytes, and a hash of them...
        // so we can tell if we have the right password
        // on decryption
        final byte[] randomBytes = new byte[4];
        rnd.nextBytes(randomBytes);
        final int toSkip = randomBytes[3] & 0xFF;

        final byte[] hashedBytes = SpritzCipher.hash(32, randomBytes);
        cipher.squeezeXOR(randomBytes);
        cipher.skip(toSkip);
        cipher.squeezeXOR(hashedBytes);
        out.write(randomBytes);
        out.write(hashedBytes);

        final byte[] encKey = Arrays.copyOf(getPayloadKey(), 64);
        cipher.squeezeXOR(encKey);
        out.write(encKey);
    }
}
