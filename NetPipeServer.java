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

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;
    private static HandshakeCertificate ServerCertificate;
    private static HandshakeCertificate caCertificate;
    private static HandshakeCrypto privatek;
    static HandshakeCertificate UserCertificate;
    static HandshakeMessage SendedserverHello;
    static HandshakeMessage ReceivedclientHello;
    static HandshakeMessage ReceivedSession;
    static byte[] IV;
    static SessionKey sessionkey;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--port=<portnumber>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
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
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, NoSuchProviderException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        parseArgs(args);
        ServerSocket serverSocket = null;
        int port = Integer.parseInt(arguments.get("port"));
        ServerCertificate = returncertificate(arguments.get("usercert"));
        caCertificate = returncertificate(arguments.get("cacert"));
        FileInputStream privateKey = new FileInputStream(arguments.get("key"));
        byte[] keybytes = privateKey.readAllBytes();
        privatek = new HandshakeCrypto(keybytes);

        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }
            RecvClienthello(socket);
            ServeHello(socket);
            SessionRecv(socket);
            ServerFinished(socket);
            ReceivedClientFinished(socket);

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

    public static HandshakeCertificate returncertificate(String FilePath) throws IOException, CertificateException {
        FileInputStream Cert = new FileInputStream(FilePath);
        return new HandshakeCertificate(Cert);
    }

    public static void RecvClienthello(Socket socket) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        HandshakeMessage recvclientHello = HandshakeMessage.recv(socket);
        String usercert = recvclientHello.getParameter("Certificate");
        byte[] usercertbytes = Base64.getDecoder().decode(usercert);
        HandshakeCertificate userCertificate = new HandshakeCertificate(usercertbytes);
        userCertificate.verify(caCertificate);
        System.out.println("User certificate verified");
        //Save the message to a global variable
        UserCertificate = userCertificate;
        ReceivedclientHello = recvclientHello;
    }

    public static void ServeHello(Socket socket) throws CertificateEncodingException, IOException{
        HandshakeMessage serverHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        String servercert = Base64.getEncoder().encodeToString(ServerCertificate.getBytes());
        serverHello.putParameter("Certificate", servercert);
        serverHello.send(socket);
        SendedserverHello = serverHello;
    }

    public static void SessionRecv(Socket socket) throws IOException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        HandshakeMessage session = HandshakeMessage.recv(socket);
        byte[] sessionkeybytes = privatek.decrypt(Base64.getDecoder().decode(session.getParameter("SessionKey")));
        IV = privatek.decrypt(Base64.getDecoder().decode(session.getParameter("SessionIV")));
        sessionkey = new SessionKey(sessionkeybytes);
        ReceivedSession = session;
    }

    public static void ServerFinished(Socket socket) throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        HandshakeMessage ServerFinished = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        //Generate a digest of the serverhello message
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(SendedserverHello.getBytes());
        byte[] digestbytes = digest.digest();
        byte[] encrypteddigestbytes = privatek.encrypt(digestbytes);
        String codedencrypteddigest = Base64.getEncoder().encodeToString(encrypteddigestbytes);
        //Generate a timestamp
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        byte[] encryptedtimestampbytes = privatek.encrypt(timestamp.getBytes(StandardCharsets.UTF_8));
        String codedencryptedtimestamp = Base64.getEncoder().encodeToString(encryptedtimestampbytes);
        ServerFinished.putParameter("Signature", codedencrypteddigest);
        ServerFinished.putParameter("TimeStamp", codedencryptedtimestamp);
        ServerFinished.send(socket);
    }

    public static void ReceivedClientFinished(Socket socket) throws IOException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        HandshakeMessage recvclientFinished = HandshakeMessage.recv(socket);
        String clientfinishedcoded = recvclientFinished.getParameter("Signature");
        byte[] clientfinishedencrypted = Base64.getDecoder().decode(clientfinishedcoded);
        HandshakeCrypto publick = new HandshakeCrypto(UserCertificate);
        byte[] clientfinished = publick.decrypt(clientfinishedencrypted);
        HandshakeDigest digest = new HandshakeDigest();
        digest.update(ReceivedclientHello.getBytes());
        digest.update(ReceivedSession.getBytes());
        byte[] excepcteddigest = digest.digest();
        if (Arrays.equals(excepcteddigest,clientfinished)){
            System.out.println("Digest Verified");
        }
        else{
            System.out.println("Digest Not Verified");
        }
        String timestampcoded = recvclientFinished.getParameter("TimeStamp");
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
}
