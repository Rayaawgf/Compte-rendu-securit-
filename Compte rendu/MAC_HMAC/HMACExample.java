import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HMACExample {
    public static byte[] generateHMAC(byte[] key, byte[] data) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
            hmac.init(secretKey);
            return hmac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            // Gérer l'exception
            return null;
        }
    }
}
