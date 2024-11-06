import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Servidor {
    private static final int PUERTO = 3400;
    private static final int NUM_THREADS = 32; // Máximo número de threads según el caso
    private static final String RUTA_LLAVE_PRIVADA = "servidor_privada.key";
    private static final String RUTA_LLAVE_PUBLICA = "servidor_publica.key";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean running = true;

        while (running) {
            System.out.println("\nMenú del servidor:");
            System.out.println("1. Generar llaves asimétricas");
            System.out.println("2. Ejecutar servidor");
            System.out.println("3. Salir");
            System.out.print("Ingrese una opción: ");

            int opcion = scanner.nextInt();
            switch (opcion) {
                case 1:
                    generarLlavesAsimetricas();
                    break;
                case 2:
                    ejecutarServidor();
                    break;
                case 3:
                    running = false;
                    break;
                default:
                    System.out.println("Opción inválida");
            }
        }
        scanner.close();
    }

    private static void generarLlavesAsimetricas() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair pair = keyGen.generateKeyPair();

            // Guardar llave privada
            try (ObjectOutputStream oos = new ObjectOutputStream(
                    new FileOutputStream(RUTA_LLAVE_PRIVADA))) {
                oos.writeObject(pair.getPrivate());
            }

            // Guardar llave pública
            try (ObjectOutputStream oos = new ObjectOutputStream(
                    new FileOutputStream(RUTA_LLAVE_PUBLICA))) {
                oos.writeObject(pair.getPublic());
            }

            System.out.println("Llaves generadas y guardadas exitosamente:");
            System.out.println("Llave privada: " + RUTA_LLAVE_PRIVADA);
            System.out.println("Llave pública: " + RUTA_LLAVE_PUBLICA);

        } catch (Exception e) {
            System.err.println("Error generando las llaves: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void ejecutarServidor() {
        // Inicializar el pool de threads
        ExecutorService threadPool = Executors.newFixedThreadPool(NUM_THREADS);
        
        try {
            // Inicializar el protocolo del servidor
            ProtocoloServidor.inicializarProtocolo();

            // Crear servidor socket
            ServerSocket serverSocket = new ServerSocket(PUERTO);
            System.out.println("Servidor iniciado en puerto " + PUERTO);
            System.out.println("Esperando conexiones...");

            while (true) {
                try {
                    Socket clienteSocket = serverSocket.accept();
                    System.out.println("Cliente conectado desde: " + 
                        clienteSocket.getInetAddress().getHostAddress());
                    
                    // Crear y ejecutar nuevo thread para el cliente
                    threadPool.execute(new ThreadServidor(clienteSocket));
                    
                } catch (IOException e) {
                    System.err.println("Error aceptando conexión: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            System.err.println("Error iniciando el servidor: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static KeyPair cargarLlaves() throws Exception {
        // Cargar llave privada
        ObjectInputStream oisPrivada = new ObjectInputStream(
            new FileInputStream(RUTA_LLAVE_PRIVADA));
        PrivateKey llavePrivada = (PrivateKey) oisPrivada.readObject();
        oisPrivada.close();

        // Cargar llave pública
        ObjectInputStream oisPublica = new ObjectInputStream(
            new FileInputStream(RUTA_LLAVE_PUBLICA));
        PublicKey llavePublica = (PublicKey) oisPublica.readObject();
        oisPublica.close();

        return new KeyPair(llavePublica, llavePrivada);
    }
}