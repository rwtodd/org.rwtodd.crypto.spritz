/*
 * Copyright Richard Todd. I put the code under the
 * GPL v2.0.  See the LICENSE file in the repository.
 * for more information.
 */
package com.waywardcode.crypto;

import java.io.File;
import java.io.OutputStream;
import java.util.Optional;
import java.util.zip.DeflaterOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;

 /**
 * This is the main class used to write an encrypted stream. It
 * understands the header format, the embedded filename, and
 * the zlib compression.  If you don't want compression, use
 * a SpritzEncrypter directly.  If you don't even want a header,
 * get a SpritzCipher.cipherStream().
 * @author richard
 */
public class SpritzOutputStream implements AutoCloseable {

    private final DeflaterOutputStream deflater;
    private final SpritzEncrypter encrypter;
    private final Optional<String> internalName;
    
     /**
     * Retrieves the original, pre-encryption filename, if it was
     * stored in the encrypted file.
     * @return The original filename.
     */
    public Optional<String> getOriginalName() { return internalName; }
 
    public OutputStream getOutputStream() { return deflater; }
    
    public SpritzOutputStream(final Optional<String> fname, final String key, final OutputStream out) 
      throws IOException {
        internalName = fname;
        encrypter = new SpritzEncrypter(key, out);
        
        byte[] nameBytes = fname.map( n -> new File(n).getName() ).
                                 orElse("").
                                 getBytes(java.nio.charset.StandardCharsets.UTF_8);
        encrypter.write(nameBytes.length);
        encrypter.write(nameBytes);
        final Deflater zlibAlgo = new Deflater(Deflater.BEST_COMPRESSION);
        deflater = new DeflaterOutputStream(encrypter,zlibAlgo);
    }
    
    @Override
    public void close() throws Exception {
        deflater.finish();
        deflater.close();
        encrypter.close();
    }
    
}
