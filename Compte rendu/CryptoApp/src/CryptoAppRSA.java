import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import static org.bouncycastle.crypto.params.RSAKeyParameters.*;

public class CryptoAppRSA extends JFrame {

    private JTextArea inputData, outputData;
    private JButton encryptButton, decryptButton;
    private JComboBox<String> algorithmSelector;
    private SecretKey secretKey;
    private KeyPair rsaKeyPair; // Ajout de la paire de clés RSA

    public CryptoAppRSA() {
        setTitle("CryptoAppRSA");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel mainPanel = new JPanel(new BorderLayout());

        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        inputData = new JTextArea(10, 20);
        JScrollPane inputScrollPane = new JScrollPane(inputData);

        JPanel buttonPanel = new JPanel(new FlowLayout());
        encryptButton = new JButton("Chiffrer");
        decryptButton = new JButton("Déchiffrer");
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);

        inputPanel.add(new JLabel("Données à traiter:"), BorderLayout.NORTH);
        inputPanel.add(inputScrollPane, BorderLayout.CENTER);
        inputPanel.add(new JLabel("Algorithme:"), BorderLayout.SOUTH);

        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        outputData = new JTextArea(10, 20);
        JScrollPane outputScrollPane = new JScrollPane(outputData);

        outputPanel.add(new JLabel("Résultat:"), BorderLayout.NORTH);
        outputPanel.add(outputScrollPane, BorderLayout.CENTER);

        JPanel controlPanel = new JPanel(new FlowLayout());
        algorithmSelector = new JComboBox<>(new String[]{ "RSA"});
        controlPanel.add(new JLabel("Algorithme:"));
        controlPanel.add(algorithmSelector);
        controlPanel.add(buttonPanel);

        mainPanel.add(inputPanel, BorderLayout.WEST);
        mainPanel.add(outputPanel, BorderLayout.CENTER);
        mainPanel.add(controlPanel, BorderLayout.SOUTH);

        add(mainPanel);

        initializeKey();

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                performCryptoOperation(true);
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                performCryptoOperation(false);
            }
        });
    }

    private KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private void initializeKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(null, null);

            // Génère la paire de clés RSA
            rsaKeyPair = generateRSAKeyPair();

            // Stocke la clé publique dans le keystore
            KeyStore.Entry publicKeyEntry = new KeyStore.PrivateKeyEntry(
                    (PrivateKey) rsaKeyPair.getPublic(),
                    new java.security.cert.Certificate[]{});
            KeyStore.ProtectionParameter publicKeyProtectionParam =
                    new KeyStore.PasswordProtection("keystorepassword".toCharArray());
            keyStore.setEntry("RSAKeyAlias", publicKeyEntry, publicKeyProtectionParam);

            // Stocke la clé privée dans le keystore (à faire de manière sécurisée dans un contexte réel)
            KeyStore.Entry privateKeyEntry = new KeyStore.PrivateKeyEntry(
                    rsaKeyPair.getPrivate(),
                    new java.security.cert.Certificate[]{});
            KeyStore.ProtectionParameter privateKeyProtectionParam =
                    new KeyStore.PasswordProtection("keystorepassword".toCharArray());
            keyStore.setEntry("RSAPrivateKeyAlias", privateKeyEntry, privateKeyProtectionParam);

            // Sauvegarde le keystore dans un fichier (à faire de manière sécurisée dans un contexte réel)
            keyStore.store(new java.io.FileOutputStream("keystore.jceks"), "keystorepassword".toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String encryptRSA(String data, PublicKey publicKey) throws Exception {
        AsymmetricBlockCipher cipher = new RSAEngine();
        CipherParameters params = PublicKeyFactory.createKey(publicKey.getEncoded());
        cipher.init(true, params);

        byte[] inputBytes = data.getBytes("UTF-8");
        byte[] outputBytes = cipher.processBlock(inputBytes, 0, inputBytes.length);

        return byteArrayToHexString(outputBytes, outputBytes.length);
    }

    private String decryptRSA(String data, PrivateKey privateKey) throws Exception {
        AsymmetricBlockCipher cipher = new RSAEngine();
        CipherParameters params = PrivateKeyFactory.createKey(privateKey.getEncoded());
        cipher.init(false, params);

        byte[] inputBytes = hexStringToByteArray(data);
        byte[] outputBytes = cipher.processBlock(inputBytes, 0, inputBytes.length);

        return new String(outputBytes, "UTF-8");
    }

    private void performCryptoOperation(boolean isEncrypt) {
        String inputText = inputData.getText();
        String algorithm = (String) algorithmSelector.getSelectedItem();

        try {
            String result;
            if ("AES".equals(algorithm)) {
                // Utilise la clé AES existante
                result = isEncrypt ? encrypt(inputText, secretKey) : decrypt(inputText, secretKey);
            } else if ("RSA".equals(algorithm)) {
                // Utilise la paire de clés RSA
                result = isEncrypt ? encryptRSA(inputText, rsaKeyPair.getPublic()) : decryptRSA(inputText, rsaKeyPair.getPrivate());
            } else {
                throw new IllegalArgumentException("Algorithme non pris en charge");
            }
            outputData.setText(result);
        } catch (Exception ex) {
            ex.printStackTrace();
            outputData.setText("Erreur : " + ex.getMessage());
        }
    }

    private String encrypt(String data, SecretKey secretKey) throws Exception {
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new AESEngine());
        cipher.init(true, new org.bouncycastle.crypto.params.KeyParameter(secretKey.getEncoded()));

        byte[] inputBytes = data.getBytes("UTF-8");
        byte[] outputBytes = new byte[cipher.getOutputSize(inputBytes.length)];
        int outputLen = cipher.processBytes(inputBytes, 0, inputBytes.length, outputBytes, 0);
        outputLen += cipher.doFinal(outputBytes, outputLen);

        return byteArrayToHexString(outputBytes, outputLen);
    }

    private String decrypt(String data, SecretKey secretKey) throws Exception {
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new AESEngine());
        cipher.init(false, new org.bouncycastle.crypto.params.KeyParameter(secretKey.getEncoded()));

        byte[] inputBytes = hexStringToByteArray(data);
        byte[] outputBytes = new byte[cipher.getOutputSize(inputBytes.length)];
        int outputLen = cipher.processBytes(inputBytes, 0, inputBytes.length, outputBytes, 0);
        outputLen += cipher.doFinal(outputBytes, outputLen);

        return new String(outputBytes, 0, outputLen, "UTF-8");
    }

    private String byteArrayToHexString(byte[] array, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(String.format("%02x", array[i]));
        }
        return sb.toString();
    }

    private byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new CryptoApp().setVisible(true);
            }
        });
    }
}

