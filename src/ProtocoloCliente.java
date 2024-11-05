import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class ProtocoloCliente {

    public static void procesar (BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) 
    throws IOException{

        
        System.out.println("Escriba el mensaje ");
        String fromUser = stdIn.readLine();

        pOut.println(fromUser);

        String fromServer = "";

        if ((fromServer = pIn.readLine()) != null ){
            System.out.println("Respuesta del servidor: " + fromServer);
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
    
}
