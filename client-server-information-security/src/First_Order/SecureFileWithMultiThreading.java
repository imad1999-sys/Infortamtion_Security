package First_Order;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


// nc localhost 11111
public class SecureFileWithMultiThreading {
    public static void main(String[] args) throws IOException {
        try (ServerSocket listener = new ServerSocket(9999)) {
            System.out.println("The capitalization server is running...");
            ExecutorService pool = Executors.newFixedThreadPool(20);
            while (true) {
                pool.execute(new SecureDateServer(listener.accept()));
            }
        }
    }
}