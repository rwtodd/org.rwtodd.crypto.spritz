/*
 * Copyright Richard Todd. I put the code under the
 * GPL v2.0.  See the LICENSE file in the repository.
 * for more information.
 */
package com.waywardcode.crypto;

import static com.waywardcode.crypto.SpritzUtils.readFully;
import java.util.zip.InflaterInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.Optional;

/**
 * This is the main class used to read an encrypted stream. It
 * understands the header format, the embedded filename, and
 * the zlib compression.  If you don't want compression, use
 * a SpritzDecrypter directly.  If you don't even want a header,
 * get a SpritzCipher.cipherStream().
 * @author richard
 */
public class SpritzInputStream implements AutoCloseable {
    private final InflaterInputStream inflater;
    private final SpritzDecrypter decrypter;
    private final Optional<String> internalName;
    
    /**
     * Retrieves the original, pre-encryption filename, if it was
     * stored in the encrypted file.
     * @return The original filename.
     */
    public Optional<String> getOriginalName() { return internalName; }
    
    public SpritzInputStream(String key, InputStream is) throws IOException {
        decrypter = new SpritzDecrypter(key, is);

        int fnamelen = decrypter.read();
        if (fnamelen == -1) {
            throw new IllegalArgumentException("Instream wasn't even long enough to contain an header!");
        }
        if (fnamelen > 0) {
            final byte[] fnameBytes = new byte[fnamelen];
            if (readFully(decrypter, fnameBytes) != fnamelen) {
                throw new IllegalStateException("Instream corrupted!");
            }
            internalName = Optional.of(new String(fnameBytes, java.nio.charset.StandardCharsets.UTF_8));
        } else {
            internalName = Optional.empty();
        }

        inflater = new InflaterInputStream(decrypter);
    }
    
    /**
     * Gets an InputStream for decompressed, decrypted data.
     * @return An InputStream which can be used to read decrypted bytes 
     */
    public InputStream getInputStream() { return inflater; }
    
    @Override
    public void close() throws Exception {
        inflater.close();
        decrypter.close();
    }
    
}
