import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Created by Darren on 1/13/2017.
 */
public class EncryptionUtils {

    public static PrivateKey initPrivateKey() throws CertificateException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return initPrivateKey("ACGChatKeyStore", "1qwer$#@!".toCharArray(), "ACGChatServerSigned", "1qwer$#@!".toCharArray());
    }

    /**
     * @param fileName
     * @param keystorePassword
     * @param certificatePassword
     * @return
     */
    public static PrivateKey initPrivateKey(String fileName, char[] keystorePassword, String alias, char[] certificatePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {
        //https://stackoverflow.com/questions/3027273/how-to-store-and-load-keys-using-java-security-keystore-class

        if (fileName == null || keystorePassword == null || certificatePassword == null) {
            throw new NullPointerException("All arguments are required.");
        }

            KeyStore ks = KeyStore.getInstance("JKS");
            InputStream readStream = new FileInputStream(fileName);
            ks.load(readStream, keystorePassword);
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(certificatePassword);
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, protParam);
            PrivateKey privateKey = pkEntry.getPrivateKey();
            readStream.close();
            return privateKey;
    }

    /**
     * Loads the default server certificate to send to the client.
     *
     * @return The default server certificate to send to the client
     */
    public static X509Certificate loadServerCertificate() throws CertificateException, IOException {
        return loadCertificate("ACGChatServerSigned.cert");
    }

    /**
     * Loads the default certificate authority for verificaition of server certification
     *
     * @return The default certication authority certificate.
     */
    public static X509Certificate loadCACertificate() throws CertificateException, IOException {
        return loadCertificate("ACGChatCA.cert");
    }

    /**
     * https://stackoverflow.com/questions/24137463/how-to-load-public-certificate-from-pem-file/24139603
     *
     * @param fileName
     * @return
     */
    public static X509Certificate loadCertificate(String fileName) throws CertificateException, IOException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        FileInputStream fis = new FileInputStream(fileName);
        X509Certificate cert = (X509Certificate) factory.generateCertificate(fis);
        fis.close();
        return cert;
    }

    //http://stackoverflow.com/questions/6629473/validate-x-509-certificate-agains-concrete-ca-java
    public static void verifyCertificates(X509Certificate CACert, X509Certificate serverCert) throws CertificateException {

        if (CACert == null || serverCert == null) {
            throw new IllegalArgumentException("Certificate not found");
        }

        if (!CACert.equals(serverCert)) {
            try {
                serverCert.verify(CACert.getPublicKey());
            } catch (Exception e) {
                throw new CertificateException("Certificate not trusted", e);
            }
        }

        try {
            serverCert.checkValidity();
        } catch (Exception e) {
            throw new CertificateException("Certificate not trusted. It has expired", e);
        }

    }

    public interface AlgorithmHelper {
        Cipher getCipher();

        byte[] encrypt(byte[] object) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException;

        byte[] decrypt(byte[] encobject) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException;
    }

    public interface SymmetricAlgorithmHelper extends AlgorithmHelper {
        SecretKey getSecretKey();
    }

    public static class AESHelper implements SymmetricAlgorithmHelper {

        private Cipher cipher;
        private SecretKey secretKey;
        private IvParameterSpec ivParameterSpec;

        public AESHelper(SecretKey secretKey, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException {
            this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            this.ivParameterSpec = new IvParameterSpec(iv);
            this.secretKey = secretKey;
        }

/*        public AESHelper (SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException {
            this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            this.secretKey = secretKey;
        }*/

        public Cipher getCipher() {
            return cipher;
        }

        public SecretKey getSecretKey() {
            return secretKey;
        }

        public byte[] encrypt(byte[] object) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
/*            if (ivParameterSpec != null)*/
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
/*            else
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);*/
            return cipher.doFinal(object);
        }

        public byte[] decrypt(byte[] encobject) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
/*            if (ivParameterSpec != null)*/
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
/*            else
                cipher.init(Cipher.DECRYPT_MODE, secretKey);*/
            return cipher.doFinal(encobject);
        }

        public byte[] getIV() {
            if (ivParameterSpec != null)
                return ivParameterSpec.getIV();
            return cipher.getIV();
        }

    }

    public interface AsymmetricAlgorithmHelper extends AlgorithmHelper {
        PublicKey getPublicKey();

        PrivateKey getPrivateKey();

        byte[] sign(byte[] object) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

        byte[] unsign(byte[] encobject) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

        boolean canEncrypt();

        boolean canDecrypt();
    }

    public static class RSAHelper implements AsymmetricAlgorithmHelper {

        private Cipher cipher;
        private PublicKey publicKey;
        private PrivateKey privateKey;

        public RSAHelper(PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException {
            this(publicKey, null);
        }

        public RSAHelper(PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException {
            this(null, privateKey);
        }

        public RSAHelper(PublicKey publicKey, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException {
            this.cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public Cipher getCipher() {
            return cipher;
        }

        public byte[] encrypt(byte[] object) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(object);
        }

        public byte[] decrypt(byte[] encobject) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(encobject);
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public byte[] sign(byte[] object) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return cipher.doFinal(object);
        }

        public byte[] unsign(byte[] encobject) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return cipher.doFinal(encobject);
        }

        public boolean canEncrypt() {
            return publicKey != null;
        }

        public boolean canDecrypt() {
            return privateKey != null;
        }

    }

}
