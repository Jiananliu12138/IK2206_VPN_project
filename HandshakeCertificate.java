import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {
    private X509Certificate cert;

    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     * Obtain Handshake Certificate from Original Certificate
     */
    HandshakeCertificate(InputStream instream) throws IOException, CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        this.cert = (X509Certificate) cf.generateCertificate(instream);
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     * If the input is a character array, turn it into an input stream first
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream instream = new ByteArrayInputStream(certbytes);
        this.cert = (X509Certificate) cf.generateCertificate(instream);
    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateEncodingException {
        return cert.getEncoded();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return cert;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        cacert.getCertificate().checkValidity();
        cert.verify(cacert.getCertificate().getPublicKey());
    }

    /*
     * Return CN (Common Name) of subject
     * GetName obtains the most effective part of the information, separated by commas.
     * We search for the string CN=and take the content after it
     */
    public String getCN() {
        X500Principal subject = cert.getSubjectX500Principal();
        String parts = subject.getName(X500Principal.RFC2253);
        String[] tokens = parts.split(",");
        for (String token : tokens) {
            if (token.startsWith("CN=")) {
                return token.substring(3);
            }
        }
        return null;
    }

    /*
     * return email address of subject
     * This is a non-standard extension to X.509 certificates
     * The EMAILADDRESS property is not a standard property in the X.500 specification,
     * so Java uses the OID to identify it when using getName().
     * OID 1.2.840.113549.1.9.1 corresponds to EMAILADDRESS,
     * #1614636c69656e7440696b323230362e6b74682e7365 is the ASN.1 hexadecimal encoding of the value.
     * We need to convert the hexadecimal back to a normal string.
     * 16 is the ASN.1 type identifier indicating that this is an IA5String (ASCII string).
     * 14636c69656e7440696b323230362e6b74682e7365 is the actual string value(All information is currently being debugged)
     */
    public String getEmail() {
        X500Principal subject = cert.getSubjectX500Principal();
        String parts = subject.getName(X500Principal.RFC2253);
        String[] tokens = parts.split(",");
        for (String token : tokens) {
            if (token.startsWith("1.2.840.113549.1.9.1=#")) {
                return hexToString(token.substring(22));
            }
        }
        return null;
    }
    public static String hexToString(String hex) {
        StringBuilder output = new StringBuilder();
        for (int i = 4; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }
}
