package First_Order;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;


public class SecureDateClient {

    public static void main(String[] args) throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        try (Socket socket = new Socket("127.0.0.1", 9999)) {
            System.out.println("Enter the fileName then Ctrl+D or Ctrl+C to quit");
            Scanner scanner = new Scanner(System.in);
            Scanner in = new Scanner(socket.getInputStream());
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            while (scanner.hasNextLine()) {
                out.println(scanner.nextLine());
                System.out.println(in.nextLine());
                Scanner sc = new Scanner (System.in);
                String choice = sc.nextLine();
                out.println(choice);
                System.out.println(in.nextLine());
                Scanner sc2 = new Scanner(System.in);
                String Content = sc2.nextLine();
                out.println(Content);
                System.out.println(in.nextLine());
               // System.out.println(decrypt(in.nextLine()));
            }
        } catch (Exception e) {
            System.out.println("Error");
        }
    }

}
