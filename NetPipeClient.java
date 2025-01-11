import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import static java.lang.Math.abs;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;
    private static HandshakeCertificate clientCertificate;
    private static HandshakeCertificate caCertificate;
    private static HandshakeCrypto privatek;
    static HandshakeCertificate ServCertificate;
    //The return value of a function needs to be saved as a global variable for other functions to call
    static HandshakeMessage SendedclientHello;
    static HandshakeMessage Sendedsession;
    static HandshakeMessage ReceivedserverHello;
    static SessionKey sessionkey;
    static byte[] IV;



    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    //Use the Arguments extension class we wrote to set key value pairs.
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert","You can provide a PEM format certificate file for the user");
        arguments.setArgumentSpec("cacert","You can provide a PEM format CA certificate file");
        arguments.setArgumentSpec("key","You can provide a DER format private key file");

        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
           usage();
        }
    }
    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, ClassNotFoundException, SignatureException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Socket socket = null;
        parseArgs(args);
        //Command line reading
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        clientCertificate = returncertificate(arguments.get("usercert"));
        caCertificate = returncertificate(arguments.get("cacert"));
        FileInputStream privateKey = new FileInputStream(arguments.get("key"));
        byte[] keybytes = privateKey.readAllBytes();
        privatek = new HandshakeCrypto(keybytes);

        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }
        ClientHello(socket);
        RecvServerHello(socket);
        Sessionsend(socket);
        RecvServerFinished(socket);
        ClientFinished(socket);
        try {
            SessionCipher sessionCipher = new SessionCipher(sessionkey, IV);
            OutputStream securityos = sessionCipher.openEncryptedOutputStream(socket.getOutputStream());
            InputStream securityis = sessionCipher.openDecryptedInputStream(socket.getInputStream());
            Forwarder.forwardStreams(System.in, System.out, securityis, securityos, socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }
    //Read input certificate to generate Handshakecertificate
    public static HandshakeCertificate returncertificate(String FilePath) throws IOException, CertificateException {
        FileInputStream Cert = new FileInputStream(FilePath);
        return new HandshakeCertificate(Cert);
    }
    //Send ClientHello message
    public static void ClientHello(Socket socket) throws CertificateEncodingException, IOException {
        HandshakeMessage clientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        String clientcert = Base64.getEncoder().encodeToString(clientCertificate.getBytes());
        clientHello.putParameter("Certificate", clientcert);
        clientHello.send(socket);
        //Save the message to a global variable
        SendedclientHello = clientHello;
    }
    public static void RecvServerHello(Socket socket) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        HandshakeMessage recvserverHello = HandshakeMessage.recv(socket);
        String servercert = recvserverHello.getParameter("Certificate");
        byte[] servercertbytes = Base64.getDecoder().decode(servercert);
        HandshakeCertificate servCertificate = new HandshakeCertificate(servercertbytes);
        servCertificate.verify(caCertificate);
        System.out.println("Server certificate verified");
        ServCertificate = servCertificate;
        ReceivedserverHello = recvserverHello;
    }
    public static void Sessionsend(Socket socket) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        HandshakeMessage SessionSend = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        //Generate a session key and IV
        sessionkey = new SessionKey(128);
        SessionCipher sessioncipher = new SessionCipher(sessionkey);
        byte[] unencryptedSessionKey = sessionkey.getKeyBytes();
        IV = sessioncipher.ivbytes;
        //Encrypt the session key and IV
        HandshakeCrypto sessionencrypt = new HandshakeCrypto(ServCertificate);
        byte[] encryptedSessionKey = sessionencrypt.encrypt(unencryptedSessionKey);
        byte[] encryptedIV = sessionencrypt.encrypt(IV);
        String encryptedSessionKeyencode = Base64.getEncoder().encodeToString(encryptedSessionKey);
        String encryptedIVencode = Base64.getEncoder().encodeToString(encryptedIV);
        SessionSend.putParameter("SessionKey", encryptedSessionKeyencode);
        SessionSend.putParameter("SessionIV", encryptedIVencode);
        SessionSend.send(socket);
        Sendedsession = SessionSend;

    }
    public static void RecvServerFinished(Socket socket) throws IOException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        //verify the digest
        HandshakeMessage recvserverFinished = HandshakeMessage.recv(socket);
        String serverfinishedcoded = recvserverFinished.getParameter("Signature");
        byte[] serverfinishedencrypted = Base64.getDecoder().decode(serverfinishedcoded);
        HandshakeCrypto publick = new HandshakeCrypto(ServCertificate);
        byte[] serverfinished = publick.decrypt(serverfinishedencrypted);
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(ReceivedserverHello.getBytes());
        byte[] exepcteddigest = digest.digest();
        if (Arrays.equals(exepcteddigest,serverfinished)){
            System.out.println("Digest Verified");
        }
        else{
            System.out.println("Digest Not Verified");
        }
        //verify the timestamp
        String timestampcoded = recvserverFinished.getParameter("TimeStamp");
        byte[] timestampencrypted = Base64.getDecoder().decode(timestampcoded);
        byte[] decrypttimestamp = publick.decrypt(timestampencrypted);
        String timestampString = new String(decrypttimestamp, StandardCharsets.UTF_8);
        DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        LocalDateTime timestamp = LocalDateTime.parse(timestampString, dateFormat);
        LocalDateTime localDateTime = LocalDateTime.now();
        long diff = Math.abs(Duration.between(timestamp, localDateTime).getSeconds());
        if (diff < 30){
            System.out.println("Timestamp Verified");
        }
        else{
            System.out.println("Timestamp Not Verified");
        }
    }

    public static void ClientFinished(Socket socket) throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        HandshakeMessage ClientFinished = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(SendedclientHello.getBytes());
        digest.update(Sendedsession.getBytes());
        byte[] digestbytes = digest.digest();
        byte[] encrypteddigestbytes = privatek.encrypt(digestbytes);
        String codedencrypteddigest = Base64.getEncoder().encodeToString(encrypteddigestbytes);

        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        byte[] encryptedtimestampbytes = privatek.encrypt(timestamp.getBytes(StandardCharsets.UTF_8));
        String codedencryptedtimestamp = Base64.getEncoder().encodeToString(encryptedtimestampbytes);
        ClientFinished.putParameter("Signature", codedencrypteddigest);
        ClientFinished.putParameter("TimeStamp", codedencryptedtimestamp);
        ClientFinished.send(socket);
    }


}

