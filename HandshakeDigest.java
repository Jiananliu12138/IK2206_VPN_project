import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {
    private final MessageDigest digest;

    /*
     * Constructor -- initialise a digest for SHA-256
     */

    public HandshakeDigest() throws NoSuchAlgorithmException {
        this.digest = MessageDigest.getInstance("SHA-256");
    }
    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        digest.update(input);
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {
        return digest.digest();
    }
};
