
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Scanner;

/*
 * The Client that can be run both as a console or a GUI
 */
public class Client {

    // for I/O
    private ObjectInputStream sInput;        // to read from the socket
    private ObjectOutputStream sOutput;        // to write on the socket
    private Socket socket;

    // if I use a GUI or not
    private ClientGUI cg;

    // the server, the port and the username
    private String server, username;
    private int port;
    //	private Key AESKey;
//	Cipher AESCipher;
    private EncryptionUtils.AESHelper aesHelper;

    /*
     *  Constructor called by console mode
     *  server: the server address
     *  port: the port number
     *  username: the username
     */
    Client(String server, int port, String username) {
        // which calls the common constructor with the GUI set to null
        this(server, port, username, null);
    }

    /*
     * Constructor call when used from a GUI
     * in console mode the ClienGUI parameter is null
     */
    Client(String server, int port, String username, ClientGUI cg) {
        this.server = server;
        this.port = port;
        this.username = username;
        // save if we are in GUI mode or not
        this.cg = cg;
    }

    /*
     * To start the dialog
     */
    public boolean start() {
        display("[SYSTEM] Connecting to server...");
        // try to connect to the server
        try {
            socket = new Socket(server, port);
        }
        // if it failed not much I can so
        catch (Exception ec) {
            display("[SYSTEM] Error connecting to server: " + ec);
            ec.printStackTrace();
            return false;
        }

        String msg = "[SYSTEM] Connection accepted: " + socket.getInetAddress() + ":" + socket.getPort();
        display(msg);

		/* Creating both Data Stream */
        try {
            sInput = new ObjectInputStream(socket.getInputStream());
            sOutput = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException eIO) {
            display("[SYSTEM] Exception creating new Input/output Streams: " + eIO);
            return false;
        }

        // Send our username to the server this is the only message that we
        // will send as a String. All other messages will be ChatMessage objects
        try {
            ///////////////////////////////////////////////
            // Send "HELLO" to server to start handshake //
            ///////////////////////////////////////////////
            sOutput.writeObject("HELLO");

            ////////////////////////////////////
            //Read "HELLO" sent by the server //
            ////////////////////////////////////
            if (!sInput.readObject().equals("HELLO")) {
                display("[SYSTEM] Invalid starting handshake");
                disconnect(); // Just disconnect the user if failed.
                return false;
            }

            /////////////////////////////////////////
            // Read certificate sent by the server //
            /////////////////////////////////////////
            X509Certificate serverCert = (X509Certificate) sInput.readObject();
            // Load CACertificate
            X509Certificate CACertificate = EncryptionUtils.loadCACertificate();
            // Verify that the server cert comes from the Certificate Authority
            EncryptionUtils.verifyCertificates(CACertificate, serverCert);

            ///////////////////////////////////////
            // Read HELLODONE sent by the server //
            ///////////////////////////////////////
            if (!sInput.readObject().equals("HELLODONE")) {
                display("[SYSTEM] Invalid starting handshake");
                disconnect();
                return false;
            }

            //////////////////////////////////////////
            // GENERATE AND SEND IV AND SESSION KEY //
            //////////////////////////////////////////
            EncryptionUtils.RSAHelper rsaHelper = new EncryptionUtils.RSAHelper(serverCert.getPublicKey());
            // Generate a random Initialization Vector for AES/CBC
            byte[] iv = new byte[16];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);
            // Send the Initialization Vector to the server so that they can have the same IV.
            sOutput.writeObject(rsaHelper.encrypt(iv));
            // Creating shared private key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            aesHelper = new EncryptionUtils.AESHelper(keyGenerator.generateKey(), iv);
            //Encrypt shared private key with server's Public Key
            sOutput.writeObject(rsaHelper.encrypt(aesHelper.getSecretKey().getEncoded()));

            ///////////////////////////////////
            // Send encrypted DONE to server //
            ///////////////////////////////////
            sOutput.writeObject(aesHelper.encrypt("DONE".getBytes()));

            //////////////////////////////
            // DECRYPT DONE FROM SERVER //
            //////////////////////////////
            byte[] serverEncDone = (byte[]) sInput.readObject();
            if (!new String(aesHelper.decrypt(serverEncDone)).equals("DONE")) {
                display("[SYSTEM] Invalid starting handshake");
                disconnect();
                return false;
            }

            /////////////////////////
            // Encrypting username //
            /////////////////////////
            //TODO add password encryption
            sOutput.writeObject(aesHelper.encrypt(username.getBytes()));
        } catch (Exception e) {
            display("[SYSTEM] Exception doing login : " + e);
            e.printStackTrace();
            disconnect();
            return false;
        }
        // creates the Thread to listen from the server
        new ListenFromServer().start();

        // success we inform the caller that it worked
        return true;
    }

    /*
     * To send a message to the console or the GUI
     */
    private void display(String msg) {
        if (cg == null)
            System.out.println(msg);      // println in console mode
        else
            cg.append(msg + "\n");        // append to the ClientGUI JTextArea (or whatever)
    }

    /*
     * To send a message to the server
     */
    void sendMessage(ChatMessage msg) {
        try {
            sOutput.writeObject(aesHelper.encrypt(Serializer.serialize(msg)));
        } catch (IOException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            display("[SYSTEM] Exception writing to server: " + e);
            e.printStackTrace();
        }
    }

    /*
     * When something goes wrong
     * Close the Input/Output streams and disconnect not much to do in the catch clause
     */
    private void disconnect() {
        try {
            if (sInput != null) sInput.close();
        } catch (Exception e) {
        } // not much else I can do
        try {
            if (sOutput != null) sOutput.close();
        } catch (Exception e) {
        } // not much else I can do
        try {
            if (socket != null) socket.close();
        } catch (Exception e) {
        } // not much else I can do

        display("[SYSTEM] Disconnected from the server.");

        // inform the GUI
        if (cg != null)
            cg.connectionFailed();

    }

    /*
     * To start the Client in console mode use one of the following command
     * > java Client
     * > java Client username
     * > java Client username portNumber
     * > java Client username portNumber serverAddress
     * at the console prompt
     * If the portNumber is not specified 1500 is used
     * If the serverAddress is not specified "localHost" is used
     * If the username is not specified "Anonymous" is used
     * > java Client
     * is equivalent to
     * > java Client Anonymous 1500 localhost
     * are eqquivalent
     *
     * In console mode, if an error occurs the program simply stops
     * when a GUI id used, the GUI is informed of the disconnection
     */
    public static void main(String[] args) {
        // default values
        int portNumber = 1500;
        String serverAddress = "localhost";
        String userName = "Anonymous";

        // depending of the number of arguments provided we fall through
        switch (args.length) {
            // > javac Client username portNumber serverAddr
            case 3:
                serverAddress = args[2];
                // > javac Client username portNumber
            case 2:
                try {
                    portNumber = Integer.parseInt(args[1]);
                } catch (Exception e) {
                    System.out.println("Invalid port number.");
                    System.out.println("Usage is: > java Client [username] [portNumber] [serverAddress]");
                    return;
                }
                // > javac Client username
            case 1:
                userName = args[0];
                // > java Client
            case 0:
                break;
            // invalid number of arguments
            default:
                System.out.println("Usage is: > java Client [username] [portNumber] {serverAddress]");
                return;
        }
        // create the Client object
        Client client = new Client(serverAddress, portNumber, userName);
        // test if we can start the connection to the Server
        // if it failed nothing we can do
        if (!client.start())
            return;

        // wait for messages from user
        Scanner scan = new Scanner(System.in);
        // loop forever for message from the user
        while (true) {
            System.out.print("> ");
            // read message from user
            String msg = scan.nextLine();
            // logout if message is LOGOUT
            if (msg.equalsIgnoreCase("LOGOUT")) {
                client.sendMessage(new ChatMessage(ChatMessage.LOGOUT, ""));
                // break to do the disconnect
                break;
            }
            // message WhoIsIn
            else if (msg.equalsIgnoreCase("WHOISIN")) {
                client.sendMessage(new ChatMessage(ChatMessage.WHOISIN, ""));
            } else {                // default to ordinary message
                client.sendMessage(new ChatMessage(ChatMessage.MESSAGE, msg));
            }
        }
        // done disconnect
        client.disconnect();
    }

    /*
     * a class that waits for the message from the server and append them to the JTextArea
     * if we have a GUI or simply System.out.println() it in console mode
     */
    class ListenFromServer extends Thread {

        public void run() {
            while (true) {
                try {
                    byte[] encText = (byte[]) sInput.readObject();
                    String msg = new String(aesHelper.decrypt(encText));
                    // if console mode print the message and add back the prompt
                    if (cg == null) {
                        System.out.println(msg);
                        System.out.print("> ");
                    } else {
                        cg.append(msg);
                    }
                } catch (IOException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
                    display("[SYSTEM] Server has close the connection: " + e);
                    if (cg != null)
                        cg.connectionFailed();
                    break;
                }
                // can't happen with a String object but need the catch anyhow
                catch (ClassNotFoundException e2) {
                }
            }
        }
    }
}
