import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.Buffer;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Servidor {
    private static final int PUERTO = 3400;
  
                                    



    public static void servidorIterativo() throws Exception{
        ServerSocket servSock = null;
        Boolean continuar = true;
        try {
            servSock = new ServerSocket(PUERTO);
        } catch(Exception e) {
            System.err.println("Ocurrio un error");
                e.printStackTrace();
            }


            while(continuar) {
                Socket cliente = servSock.accept();
            try{
                PrintWriter escritor = new PrintWriter(cliente.getOutputStream(), true);
                BufferedReader lector = new BufferedReader(new InputStreamReader(cliente.getInputStream()));
                ProtocoloServidor.procesar(lector, escritor);
                escritor.close();
                lector.close();
                cliente.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        
    }

    public static void servidorDelegados(Integer N_THREADS){
    
        final ExecutorService pool = Executors.newFixedThreadPool(N_THREADS);
        ServerSocket servSock = null;
        try {
            servSock = new ServerSocket(PUERTO);
            System.out.println("Listo para recibir conexiones");
            
            while(true) {
                Socket cliente = servSock.accept();
                pool.execute((Runnable) new ProtocoloServidor(cliente));
            }
        } catch(Exception e) {
            System.err.println("Ocurrio un error");
            e.printStackTrace();
        } finally {
            try {
                servSock.close();
            } catch(Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String args[]) throws Exception {

        Scanner scanner = new Scanner(System.in);
        boolean running = true;
        Datos.UpdateData();
        while (running) {
            System.out.println("\nMenú del servidor:");
            System.out.println("1. Generar llaves asimétricas");
            System.out.println("2. Ejecutar servidor");
            System.out.println("3. Salir");
            System.out.print("Ingrese una opción: ");

            int opcion = scanner.nextInt();
            switch (opcion) {
                case 1:
                    Seguridad.NuevasLlaves();
                    System.out.println("Llaves generadas");
                case 2:
                    System.out.println("\nSeleccione el tipo de servidor:\n");
                    System.out.println("1. Servidor iterativo");
                    System.out.println("2. Servidor con delegados");
                    int tipoServidor = scanner.nextInt();
                    switch (tipoServidor) {
                        case 1:
                            servidorIterativo();
                            break;
                        case 2:
                            System.out.print("Ingrese el número de threads: ");
                            int nThreads = scanner.nextInt();
                            servidorDelegados(nThreads);
                            break;
                        default:
                            System.out.println("Opción inválida");
                    }
                case 3:
                    running = false;
                    break;
                default:
                    System.out.println("Opción inválida");
            }
        }
        scanner.close();
}


}
