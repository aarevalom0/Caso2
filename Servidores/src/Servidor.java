import java.net.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;

public class Servidor {
    private static final int PUERTO = 3400;
    public PublicKey llavePublica;
    private PrivateKey llavePrivada;
    private static String output = "";
    
        @SuppressWarnings("deprecation")
        public static void main(String[] args) throws IOException {
            iniciarServidorConcurrente();
            System.out.println("Seleccione una opción:");
            System.out.println("1. Generar llaves RSA");
            System.out.println("2. Iniciar servidor concurrente");
            
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            int opcion = Integer.parseInt(reader.readLine());

            if (opcion == 1) {
                generarLlavesRSA();
            } else if (opcion == 2) {
                iniciarServidorConcurrente();
            } else {
                System.out.println("Opción no válida.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void generarLlavesRSA() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair parLlaves = keyGen.generateKeyPair();
            try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("llave_privada.ser"))) {
                out.writeObject(parLlaves.getPrivate());
            }
            try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("llave_publica.ser"))) {
                out.writeObject(parLlaves.getPublic());
            }
            System.out.println("Llaves RSA generadas y guardadas.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void iniciarServidorConcurrente() {
        try (ServerSocket servidor = new ServerSocket(PUERTO)) {
            System.out.println("Servidor iniciado en el puerto " + PUERTO);

            while (true) {
                Socket socketCliente = servidor.accept();
                new Thread(new ThreadServidor(socketCliente)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
