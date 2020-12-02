package PGP;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class SecureFileServer_PGP implements Runnable {
    private static final String key = "aesEncryptionKey";
    private static final String initVector = "encryptionIntVec";
    private Socket socket;
    public SecureFileServer_PGP(Socket socket) {
        this.socket = socket;
    }


    private static String encrypt(String data) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("PGP");
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

    @Override
    public void run() {
        System.out.println("connected:" +socket);
        try {
            Scanner in = new Scanner(socket.getInputStream());
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            while (in.hasNextLine()) {
                //view
                // System.out.println("the file name in encrypt "+in.nextLine());
                String fileName = decrypt(in.nextLine());
                //System.out.println("the file name in decrypt "+
                System.out.println("Enter Your Choice");
                Scanner scanner = new Scanner (System.in);
                String choice = scanner.nextLine();
                switch (choice){
                    case "view": {
                        File file = new File("E:\\imad\\" + fileName);
                        BufferedReader br = new BufferedReader(new FileReader(file));

                        String st;
                        while ((st = br.readLine()) != null) {

                            // System.out.println("the data file in decrypt "+st);
                            // System.out.println("the data file in encrypt "+encrypt(st));
                            out.println(encrypt(st));
                        }
                        break;
                    }
                    case "edit":{
                        File file = new File("E:\\imad\\" + fileName);

                    }
                }
                break;
            }
        } catch (Exception e) {
            System.out.println("Error:" + socket);
        } finally {
            try { socket.close(); } catch (IOException e) {}
            System.out.println("Closed: " + socket);
        }
    }
}
