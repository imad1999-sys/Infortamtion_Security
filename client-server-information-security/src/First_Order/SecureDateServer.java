package First_Order;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

// nc localhost 11111
public class SecureDateServer implements Runnable {

    private Socket socket;
    public SecureDateServer(Socket socket) {
        this.socket = socket;
    }




    @Override
    public void run() {
        System.out.println("connected:" +socket);
        try {
            Scanner in = new Scanner(socket.getInputStream());
           // System.out.println("The fileName is : " + in.nextLine());
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            while (in.hasNextLine()) {
                //view

                String fileName = in.nextLine();

                out.println("Enter Your Choice");
                Scanner sc = new Scanner(socket.getInputStream());
                String choice = sc.nextLine();
                System.out.println(choice);
                switch (choice){
                    case "view": {
                        File file = new File("E:\\imad\\" + fileName);
                        BufferedReader br = new BufferedReader(new FileReader(file));

                        String st;
                        while ((st = br.readLine()) != null) {


                            out.println(st);
                        }
                        break;
                    }
                    case "edit":{
                        try{

                            FileWriter myWriter = new FileWriter("E:\\imad\\" + fileName);
                            out.println("enter the text");
                            Scanner sc2 = new Scanner(socket.getInputStream());
                            String Content = sc2.nextLine();
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
            try { socket.close(); } catch (IOException e) {}
            System.out.println("Closed: " + socket);
        }
    }
}
