import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;


public class Cliente {

    public static final int PUERTO = 3400;
    public static final String SERVIDOR = "localhost";
    private Socket socket;
    private PrintWriter escritor;
    private BufferedReader lector;
    private BufferedReader stdIn;
    private int id;
    private int idPaquete;

    public Cliente() throws IOException {
        inicializarSocket();
    }

    private void inicializarSocket() throws IOException {
        try {
           
            socket = new Socket(SERVIDOR, PUERTO);
            
            
            escritor = new PrintWriter(socket.getOutputStream(), true);
            lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            stdIn = new BufferedReader(new InputStreamReader(System.in));
            
            System.out.println("Cliente conectado...");
            
        } catch (IOException e) {

            e.printStackTrace();
            System.exit(-1);
        }

        
    }

    public static String leerLLave(String nombreArchivo) {
        StringBuilder contenido = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(nombreArchivo))) {
            String linea;
            while ((linea = br.readLine()) != null) {
                contenido.append(linea).append("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
         String llave = contenido.toString();
        return llave;
    }

    private final static String PADDING = "";

    
    public static byte[] cifrar(SecretKey llave, String texto){
        byte[] textoCifrado;
        try{
            Cipher cifrador = Cipher.getInstance(PADDING);
            byte[] textoClaro = texto.getBytes();

            cifrador.init(Cipher.ENCRYPT_MODE, llave);
            textoCifrado = cifrador.doFinal(textoClaro);

            return textoCifrado;
        } catch (Exception e){
            System.err.println("Exception: " + e.getMessage());
            return null;
        }
    }



    public void ejecutar() throws IOException {
        try {
            
            ProtocoloCliente.procesar(stdIn, lector, escritor);
        } finally {
           
            stdIn.close();
            escritor.close();
            lector.close();
            socket.close();
        }
    }


}