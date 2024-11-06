import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class Cliente {
    public static final int PUERTO = 3400;
    public static final String SERVIDOR = "localhost";

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Digite cantidad de clientes:");
       
        int opcion = scanner.nextInt();
        for (int i = 0; i < opcion; i++) {
            try {
                Socket socket = new Socket(SERVIDOR, PUERTO);
                PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                ProtocoloCliente.procesar(lector, escritor);
                
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        
    }
}