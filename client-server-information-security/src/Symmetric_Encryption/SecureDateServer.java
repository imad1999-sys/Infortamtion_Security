package Symmetric_Encryption;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

// nc localhost 11111
public class SecureDateServer implements Runnable {
    private static final String key = "aesEncryptionKey";
    private static final String initVector = "encryptionIntVec";
    public static String session_key;
    private Socket socket;

    public SecureDateServer(Socket socket) {
        this.socket = socket;
    }
    private static String encrypt(String data) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] decodedKey = Base64.getDecoder().decode(session_key);
        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes());

        SecretKey skeySpec= new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv); // or Cipher.DECRYPT_MODE

        byte[] encrypted = cipher.doFinal(data.getBytes());

        String s = Base64.getEncoder().encodeToString(encrypted);
        System.out.println(s);
        return s;
    }
    private String decrypt(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] encrypted = Base64.getDecoder().decode(data);

        IvParameterSpec iv = new IvParameterSpec(initVector.getBytes());

        byte[] decodedKey = Base64.getDecoder().decode(session_key);

        SecretKey skeySpec= new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] decrypted = cipher.doFinal(encrypted);

        String s = new String(decrypted, StandardCharsets.UTF_8);

        return s;
    }

    @Override
    public void run() {
        //Creating KeyPair generator object
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
        System.out.println("connected:" + socket);
        try {
            Scanner in = new Scanner(socket.getInputStream());
            Scanner in2 = new Scanner(socket.getInputStream());
            Scanner in3 = new Scanner(socket.getInputStream());
            // System.out.println("The fileName is : " + in.nextLine());
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());

            out.println(publicKeyString);

            String pub_key_client = in.nextLine();

            //convert string public key to class
            byte[] Bytes = Base64.getDecoder().decode(pub_key_client);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Bytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PublicKey clientPublicKey = keyFactory.generatePublic(keySpec);

            System.err.println("the pub_key of client is " + pub_key_client);
            out.println("enter the session key");
//Recive Session key
            session_key = in2.nextLine();
            System.err.println("the session key is " + session_key);
            // Decrypt the session key
            byte[] encrypted = Base64.getDecoder().decode(session_key);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privKey);
            byte[] decrypted = cipher.doFinal(encrypted);
            // print the decryption result
            System.err.println(new String(decrypted, StandardCharsets.UTF_8));
            session_key = new String(decrypted, StandardCharsets.UTF_8);

            out.println("the session key is available in server");

            while (in.hasNextLine()) {
                //view

                String fileName = decrypt(in.nextLine());
                System.out.println(fileName);
                out.println("Enter Your Choice");
                Scanner sc = new Scanner(socket.getInputStream());
                String choice = sc.nextLine();
                System.out.println(choice);
                switch (choice) {
                    case "view": {
                        File file = new File("E:\\imad\\" + fileName);
                        BufferedReader br = new BufferedReader(new FileReader(file));

                        String st;
                        while ((st = br.readLine()) != null) {


                            out.println(encrypt(st));
                        }
                        break;
                    }
                    case "edit": {
                        try {

                            FileWriter myWriter = new FileWriter("E:\\imad\\" + fileName);
                            out.println("enter the text");
                            Scanner sc2 = new Scanner(socket.getInputStream());
                            //System.out.println(sc2.nextLine());
                            String Content = decrypt(sc2.nextLine());
                            myWriter.write(Content);
                            myWriter.close();
                            out.println("Successfully wrote to the file.");
                        } catch (IOException e) {
                            System.out.println("An error occurred.");
                            e.printStackTrace();
                        }

                    }
                }
                break;
            }
        } catch (Exception e) {
            System.out.println("Error:" + socket);
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
            }
            System.out.println("Closed: " + socket);
        }
    }
}
