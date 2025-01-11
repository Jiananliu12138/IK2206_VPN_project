import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {
	private PublicKey publicKey;
	private PrivateKey privateKey;
	Boolean mode;
	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
		X509Certificate cert = handshakeCertificate.getCertificate();
		this.publicKey = cert.getPublicKey();
		this.mode = true;
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */

	public HandshakeCrypto(byte[] keybytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keybytes);
		this.privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);
		this.mode = false;
	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		if (mode) {
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
		} else {
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
		}
		cipher.update(ciphertext);
		return cipher.doFinal();
	}

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte [] encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        if (mode) {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        }
        cipher.update(plaintext);
        return cipher.doFinal();
    }

}
