import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class Cliente {
    public static final int PUERTO = 3400;
    public static final String SERVIDOR = "localhost";

    static class ClienteWorker implements Runnable {
        private final int clienteId;
        public ClienteWorker(int clienteId) {
            this.clienteId = clienteId;
        }
        @Override
        public void run() {
            try (
                Socket socket = new Socket(SERVIDOR, PUERTO);
                PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()))
            ) {
                System.out.println("Cliente " + clienteId + " conectado");
                ProtocoloCliente.procesar(lector, escritor, clienteId%32, clienteId%6);
                System.out.println("Cliente " + clienteId + " terminó");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Digite cantidad de clientes:");
        int numClientes = scanner.nextInt();
        ExecutorService executor = Executors.newFixedThreadPool(numClientes); 
        System.out.println("Iniciando " + numClientes + " clientes...");
        
        try {
            for (int i = 0; i < numClientes; i++) {
                executor.execute(new ClienteWorker(i));
            }
            executor.shutdown();
            
        } finally {
            scanner.close();
        }
        
        System.out.println("Todos los clientes han terminado");
    }
    
    
}