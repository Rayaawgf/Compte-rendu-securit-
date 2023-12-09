import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        // Exemple 1: HMAC
        byte[] hmacKey = "myHMACKey".getBytes();
        byte[] hmacData = "Hello, HMAC!".getBytes();

        byte[] hmacResult = generateHMAC(hmacKey, hmacData);

        if (hmacResult != null) {
            System.out.println("HMAC: " + Arrays.toString(hmacResult));
        } else {
            System.out.println("Erreur lors de la génération du HMAC.");
        }

        // Exemple 2: MAC
        byte[] macKey = "myMACKey".getBytes();
        byte[] macData = "Hello, MAC!".getBytes();

        byte[] macResult = generateMAC(macKey, macData);

        if (macResult != null) {
            System.out.println("MAC: " + Arrays.toString(macResult));
        } else {
            System.out.println("Erreur lors de la génération du MAC.");
        }
    }

    private static byte[] generateHMAC(byte[] key, byte[] data) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
            hmac.init(secretKey);
            return hmac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] generateMAC(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
            mac.init(secretKey);
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

}
