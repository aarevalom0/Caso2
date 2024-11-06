import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class ThreadServidor implements Runnable {
    private Socket socket;

    public ThreadServidor(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try (DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

            // Leer ID de cliente y paquete
            String clienteID = in.readUTF();
            String paqueteID = in.readUTF();

            // Consulta del estado
            String estado = consultarEstado(clienteID, paqueteID);

            // Cifrar el estado con AES y firmarlo con RSA
            byte[] mensajeCifrado = cifrarAES(estado);
            byte[] firma = firmarRSA(mensajeCifrado);

            // Enviar el mensaje cifrado y la firma
            out.writeInt(mensajeCifrado.length);
            out.write(mensajeCifrado);
            out.writeInt(firma.length);
            out.write(firma);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private String consultarEstado(String clienteID, String paqueteID) {
        // Lógica de consulta del estado (dummy para este ejemplo)
        return "ENOFICINA";
    }

    private byte[] cifrarAES(String texto) throws Exception {
        Key llaveAES = new SecretKeySpec("1234567890123456".getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);  // Vector de inicialización
        cipher.init(Cipher.ENCRYPT_MODE, llaveAES, iv);
        return cipher.doFinal(texto.getBytes());
    }

    private byte[] firmarRSA(byte[] datos) throws Exception {
        Signature firma = Signature.getInstance("SHA1withRSA");
        PrivateKey llavePrivada = (PrivateKey) new ObjectInputStream(new FileInputStream("llave_privada.ser")).readObject();
        firma.initSign(llavePrivada);
        firma.update(datos);
        return firma.sign();
    }
}
