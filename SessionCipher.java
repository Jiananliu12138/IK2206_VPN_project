import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class SessionCipher {
    SessionKey key;
    byte[] ivbytes;
    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) {
        this.key = key;
        SecureRandom random = new SecureRandom();
        this.ivbytes = new byte[16];
        random.nextBytes(ivbytes);
    }
    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes) {
        this.key = key;
        this.ivbytes = ivbytes;
    }
    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return key;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return ivbytes;
    }
    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivbytes = new IvParameterSpec(this.ivbytes);
        cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), ivbytes);
        return new CipherOutputStream(os, cipher);
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivbytes = new IvParameterSpec(this.ivbytes);
        cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(), ivbytes);
        return new CipherInputStream(inputstream, cipher);
    }
}
