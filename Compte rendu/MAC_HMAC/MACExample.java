import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MACExample {
    public static byte[] generateMAC(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("AES");
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            mac.init(secretKey);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            // Gérer l'exception
            return null;
        }
    }
}
