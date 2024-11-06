import java.io.*;
import java.net.*;
import java.security.*;
import java.math.BigInteger;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Cliente {
    private static final String SERVIDOR = "localhost";
    private static final int PUERTO = 3400;
    private static final List<String> ESTADOS = new ArrayList<>(Arrays.asList(
        "ENOFICINA", "RECOGIDO", "ENCLASIFICACION", "DESPACHADO", 
        "ENENTREGA", "ENTREGADO", "DESCONOCIDO"
    ));

    public static void main(String[] args) {
        try {
            // Inicializar el protocolo del cliente
            ProtocoloCliente.inicializarProtocolo("servidor_publica.key");
            
            try (Socket socket = new Socket(SERVIDOR, PUERTO);
                 DataInputStream in = new DataInputStream(socket.getInputStream());
                 DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
                
                // 1. Recibir parámetros DH del servidor
                BigInteger p = new BigInteger(in.readUTF(), 16);
                BigInteger g = new BigInteger(in.readUTF(), 16);
                BigInteger gx = new BigInteger(in.readUTF(), 16);
                byte[] firmaDH = new byte[in.readInt()];
                in.readFully(firmaDH);

                // 2. Establecer llaves maestras
                ProtocoloCliente.establecerLlavesMaestras(g, p, gx);

                // 3. Solicitar datos al usuario
                Scanner scanner = new Scanner(System.in);
                System.out.print("Ingrese el ID de usuario: ");
                int idUsuario = scanner.nextInt();
                System.out.print("Ingrese el ID de paquete: ");
                int idPaquete = scanner.nextInt();

                // 4. Cifrar y firmar la consulta
                byte[] consultaCifrada = ProtocoloCliente.cifrarConsulta(idUsuario, idPaquete);
                byte[] firmaConsulta = ProtocoloCliente.firmarConsulta(idUsuario, idPaquete);

                // 5. Enviar consulta cifrada y firma al servidor
                out.writeInt(consultaCifrada.length);
                out.write(consultaCifrada);
                out.writeInt(firmaConsulta.length);
                out.write(firmaConsulta);

                // 6. Recibir respuesta del servidor
                byte[] respuestaCifrada = new byte[in.readInt()];
                in.readFully(respuestaCifrada);
                byte[] firmaRespuesta = new byte[in.readInt()];
                in.readFully(firmaRespuesta);

                // 7. Verificar respuesta
                if (ProtocoloCliente.verificarRespuesta(respuestaCifrada, firmaRespuesta)) {
                    // Descifrar y mostrar el estado
                    Cipher descifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    descifrador.init(Cipher.DECRYPT_MODE, 
                                   ProtocoloCliente.getLlaveEncriptacion(), 
                                   ProtocoloCliente.getIV());
                    byte[] estadoBytes = descifrador.doFinal(respuestaCifrada);
                    int estado = bytesToInt(estadoBytes);
                    System.out.println("Estado del paquete: " + formatearEstado(estado));
                } else {
                    System.out.println("Error en la consulta");
                }
            }
            
        } catch (Exception e) {
            System.err.println("Error en el cliente: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static PublicKey cargarLlavePublicaServidor() throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream("servidor_publica.key"))) {
            return (PublicKey) ois.readObject();
        }
    }
    
    private static boolean verificarIntegridad(int estadoPaquete, PublicKey serverPublicKey) 
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        try {
            byte[] datos = intToBytes(estadoPaquete);
            Signature verificador = Signature.getInstance("SHA1withRSA");
            verificador.initVerify(serverPublicKey);
            verificador.update(datos);
            // En un caso real, aquí verificaríamos la firma recibida del servidor
            return true;
        } catch (Exception e) {
            System.err.println("Error verificando integridad: " + e.getMessage());
            return false;
        }
    }
    
    private static String formatearEstado(int estadoPaquete) {
        if (estadoPaquete >= 0 && estadoPaquete < ESTADOS.size()) {
            return ESTADOS.get(estadoPaquete);
        }
        return ESTADOS.get(ESTADOS.size() - 1); // Estado DESCONOCIDO
    }

    private static byte[] intToBytes(int value) {
        return new byte[] {
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value
        };
    }

    private static int bytesToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
               ((bytes[1] & 0xFF) << 16) |
               ((bytes[2] & 0xFF) << 8) |
               (bytes[3] & 0xFF);
    }
}