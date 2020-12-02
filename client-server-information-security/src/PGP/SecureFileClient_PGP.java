package PGP;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class SecureFileClient_PGP {
    private static final String key = "aesEncryptionKey";
    private static final String initVector = "encryptionIntVec";

    public static void main(String[] args) throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        try (Socket socket = new Socket("127.0.0.1", 11111)) {
            System.out.println("Enter lines of text then Ctrl+D or Ctrl+C to quit");
            Scanner scanner = new Scanner(System.in);
            Scanner in = new Scanner(socket.getInputStream());
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            while (scanner.hasNextLine()) {
                out.println(encrypt(scanner.nextLine()));
                System.out.println(decrypt(in.nextLine()));
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    private static String decrypt(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] encrypted = Base64.getDecoder().decode(data);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("PGP");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        keyPairGenerator.initialize(2048);

        IvParameterSpec iv = new IvParameterSpec(keyPair.getPrivate().getEncoded());
        SecretKeySpec skeySpec = new SecretKeySpec(keyPair.getPrivate().getEncoded(), "PGP");

        Cipher cipher = Cipher.getInstance("PGP/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] decrypted = cipher.doFinal(encrypted);

        String s = new String(decrypted, StandardCharsets.UTF_8);

        return s;
    }
    private static String encrypt(String data) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("PGP");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        keyPairGenerator.initialize(2048);

        IvParameterSpec iv = new IvParameterSpec(keyPair.getPublic().getEncoded());
        SecretKeySpec skeySpec = new SecretKeySpec(keyPair.getPublic().getEncoded(), "PGP");

        Cipher cipher = Cipher.getInstance("PGP/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv); // or Cipher.DECRYPT_MODE

        byte[] encrypted = cipher.doFinal(data.getBytes());

        String s = Base64.getEncoder().encodeToString(encrypted);
        System.out.println(s);
        return s;
    }
}
