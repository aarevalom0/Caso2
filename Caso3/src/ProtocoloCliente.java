import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.math.BigInteger;

import java.io.*;

public class ProtocoloCliente {
    private static final String ALGORITMO_CIFRADO = "AES/CBC/PKCS5Padding";
    private static final String ALGORITMO_FIRMA = "SHA1withRSA";
    private static final String ALGORITMO_HMAC = "HmacSHA384";

    private static SecretKeySpec llaveEncriptacion;
    private static SecretKeySpec llaveHmac;
    private static IvParameterSpec iv;
    private static PrivateKey llavePrivadaCliente;
    private static PublicKey llavePublicaServidor;

    public static void inicializarProtocolo(String rutaLlavePublicaServidor) throws Exception {
        // Cargar llave pública del servidor
        llavePublicaServidor = cargarLlavePublica(rutaLlavePublicaServidor);
        
        // Generar par de llaves RSA para el cliente
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair parLlaves = keyGen.generateKeyPair();
        llavePrivadaCliente = parLlaves.getPrivate();
        
        // Generar IV aleatorio
        SecureRandom random = new SecureRandom();
        byte[] ivBytes = new byte[16];
        random.nextBytes(ivBytes);
        iv = new IvParameterSpec(ivBytes);
    }

    public static byte[] cifrarConsulta(int idUsuario, int idPaquete) throws InvalidAlgorithmParameterException {
        try {
            Cipher cifrador = Cipher.getInstance(ALGORITMO_CIFRADO);
            cifrador.init(Cipher.ENCRYPT_MODE, llaveEncriptacion, iv);
            byte[] consultaCifrada = new byte[8];
            System.arraycopy(intToBytes(idUsuario), 0, consultaCifrada, 0, 4);
            System.arraycopy(intToBytes(idPaquete), 0, consultaCifrada, 4, 4);
            return cifrador.doFinal(consultaCifrada);
        } catch (Exception e) {
            System.err.println("Error al cifrar la consulta: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] firmarConsulta(int idUsuario, int idPaquete) {
        try {
            Signature firma = Signature.getInstance(ALGORITMO_FIRMA);
            firma.initSign(llavePrivadaCliente);
            firma.update(intToBytes(idUsuario));
            firma.update(intToBytes(idPaquete));
            return firma.sign();
        } catch (Exception e) {
            System.err.println("Error al firmar la consulta: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public static boolean verificarRespuesta(byte[] respuestaCifrada, byte[] firma) {
        try {
            // Descifrar la respuesta
            Cipher descifrador = Cipher.getInstance(ALGORITMO_CIFRADO);
            descifrador.init(Cipher.DECRYPT_MODE, llaveEncriptacion, iv);
            byte[] respuestaDescifrada = descifrador.doFinal(respuestaCifrada);
            
            // Verificar firma
            int estado = bytesToInt(respuestaDescifrada);
            Signature verificador = Signature.getInstance(ALGORITMO_FIRMA);
            verificador.initVerify(llavePublicaServidor);
            verificador.update(intToBytes(estado));
            return verificador.verify(firma);
        } catch (Exception e) {
            System.err.println("Error al verificar la respuesta: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public static void establecerLlavesMaestras(BigInteger g, BigInteger p, BigInteger gx) throws Exception {
        // Generar par de llaves DH
        Integer dhSpec = 1234539933;
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        KeyPair parLlaves = keyGen.generateKeyPair();
        
        // Calcular llave maestra
        KeyAgreement acuerdo = KeyAgreement.getInstance("DH");
        acuerdo.init(parLlaves.getPrivate());
        acuerdo.doPhase(parLlaves.getPublic(), true);
        byte[] llaveMaestra = acuerdo.generateSecret();
        
        // Generar llaves de sesión
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(llaveMaestra);
        
        // Primera mitad para cifrado, segunda para HMAC
        llaveEncriptacion = new SecretKeySpec(digest, 0, 32, "AES");
        llaveHmac = new SecretKeySpec(digest, 32, 32, ALGORITMO_HMAC);
    }

    private static PublicKey cargarLlavePublica(String rutaArchivo) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(rutaArchivo))) {
            return (PublicKey) ois.readObject();
        }
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

    public static Key getLlaveEncriptacion() {
        return llaveEncriptacion;
    }

    public static IvParameterSpec getIV() {
        return iv;
    }
}
