package Symmetric_Encryption;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;


public class SecureDateClient {
    private static final String key = "aesEncryptionKey";
    private static final String initVector = "encryptionIntVec";
    public static String pub_key_server;
    private static String session_key;

    public static void main(String[] args) throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        try (Socket socket = new Socket("127.0.0.1", 5555)) {
            KeyPairGenerator keyPairGen = null;
            try {
                keyPairGen = KeyPairGenerator.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            //Initializing the KeyPairGenerator
            keyPairGen.initialize(2048);

            //Generating the pair of keys
            KeyPair pair = keyPairGen.generateKeyPair();

            //Getting the private key from the key pair
            PrivateKey privKey = pair.getPrivate();

            //Getting the public key from the key pair
            PublicKey publicKey = pair.getPublic();

            Scanner in = new Scanner(socket.getInputStream());
            Scanner in2 = new Scanner(socket.getInputStream());
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            pub_key_server = in.nextLine();

            //convert string public key to class
            byte[] Bytes = Base64.getDecoder().decode(pub_key_server);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Bytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PublicKey serverPublicKey = keyFactory.generatePublic(keySpec);

            System.out.println("the pub_key of server is " + pub_key_server);
            String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());


            out.println(publicKeyString);

            String text = in2.nextLine();
            System.out.println(text);
            //Generate session key
            session_key = Base64.getEncoder().encodeToString(createSecret().getEncoded());
            System.out.println("the Session Key is " + session_key);

            //Encrypt the key
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] encBytes = cipher.doFinal(session_key.getBytes());
            String text2 = Base64.getEncoder().encodeToString(encBytes);
            //Send to server
            out.println(text2);

            String message = in2.nextLine();
            System.out.println(message);
            System.out.println("Enter the fileName then Ctrl+D or Ctrl+C to quit");
            Scanner scanner = new Scanner(System.in);
            while (scanner.hasNextLine()) {

                out.println(encrypt(scanner.nextLine()));
                Scanner in3 = new Scanner(socket.getInputStream());
                System.out.println(in3.nextLine());
                Scanner sc = new Scanner(System.in);
                String choice = sc.nextLine();
                out.println(choice);
                switch (choice) {
                    case "view": {
                        String decryption = in.nextLine();
                        System.out.println(decryption);
                        System.out.println(decrypt(decryption));
                        break;
                    }
                    case "edit": {
                        System.out.println(in.nextLine());
                        Scanner sc2 = new Scanner(System.in);
                        String Content = sc2.nextLine();
                        out.println(encrypt(Content));
                        System.out.println(in.nextLine());
                        // System.out.println(decrypt(in.nextLine()));
                        break;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String decrypt(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] encrypted = Base64.getDecoder().decode(data);

        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes());

        byte[] decodedKey = Base64.getDecoder().decode(session_key);

        SecretKey skeySpec = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] decrypted = cipher.doFinal(encrypted);

        String s = new String(decrypted, StandardCharsets.UTF_8);

        return s;
    }

    private static String encrypt(String data) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] decodedKey = Base64.getDecoder().decode(session_key);
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes());

        SecretKey skeySpec = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv); // or Cipher.DECRYPT_MODE

        byte[] encrypted = cipher.doFinal(data.getBytes());

        String s = Base64.getEncoder().encodeToString(encrypted);
        System.out.println(s);
        return s;
    }

    public static SecretKey createSecret() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom secRandom = new SecureRandom();
        keyGen.init(secRandom);
        Key key = keyGen.generateKey();
        return (SecretKey) key;
    }
}
