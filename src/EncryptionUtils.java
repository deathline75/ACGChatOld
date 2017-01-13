import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Created by Darren on 1/13/2017.
 */
public class EncryptionUtils {

    public static PrivateKey initPrivateKey() {
        return initPrivateKey("ACGChatKeyStore", "1qwer$#@!".toCharArray(),"1qwer$#@!".toCharArray());
    }

    /**
     *
     * @param fileName
     * @param keystorePassword
     * @param certificatePassword
     * @return
     */
    public static PrivateKey initPrivateKey(String fileName, char[] keystorePassword, char[] certificatePassword) {
        //https://stackoverflow.com/questions/3027273/how-to-store-and-load-keys-using-java-security-keystore-class

        if (fileName == null || keystorePassword == null || certificatePassword == null) {
            throw new NullPointerException("All arguments are required.");
        }

        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            InputStream readStream = new FileInputStream(fileName);
            ks.load(readStream, keystorePassword);
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(certificatePassword);
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("ACGChatServerSigned", protParam);
            PrivateKey privateKey = pkEntry.getPrivateKey();
            readStream.close();
            return privateKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Loads the default server certificate to send to the client.
     * @return The default server certificate to send to the client
     */
    public static X509Certificate loadServerCertificate(){
        return loadCertificate("ACGChatServerSigned.cert");
    }

    /**
     * Loads the default certificate authority for verificaition of server certification
     * @return The default certication authority certificate.
     */
    public static X509Certificate loadCACertificate(){
        return loadCertificate("ACGChatCA.cert");
    }

    /**
     * https://stackoverflow.com/questions/24137463/how-to-load-public-certificate-from-pem-file/24139603
     * @param fileName
     * @return
     *
     */
    public static X509Certificate loadCertificate(String fileName) {
        try{
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream(fileName);
            X509Certificate cert = (X509Certificate) factory.generateCertificate(fis);
            fis.close();
            return cert;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    //http://stackoverflow.com/questions/6629473/validate-x-509-certificate-agains-concrete-ca-java
    public static void verifyCertificates(X509Certificate CACert, X509Certificate serverCert) throws CertificateException{

        if(CACert == null || serverCert == null){
            throw new IllegalArgumentException("Certificate not found");
        }

        if(!CACert.equals(serverCert)){
            try{
                serverCert.verify(CACert.getPublicKey());
            }catch(Exception e){
                throw new CertificateException("Certificate not trusted", e);
            }
        }

        try{
            serverCert.checkValidity();
        }catch (Exception e){
            throw new CertificateException("Certificate not trusted. It has expired", e);
        }

    }

}
