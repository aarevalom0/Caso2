import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.math.BigInteger;
import java.util.ArrayList;


public class ProtocoloServidor {
    private static final String ALGORITMO_CIFRADO = "AES/CBC/PKCS5Padding";
    private static final String ALGORITMO_FIRMA = "SHA1withRSA";
    private static final String ALGORITMO_HMAC = "HmacSHA384";

    private static SecretKeySpec llaveEncriptacion;
    private static SecretKeySpec llaveHmac;
    private static IvParameterSpec iv;
    private static SecureRandom random = new SecureRandom();
    private static KeyPair parLlavesServidor;

    public static void inicializarProtocolo() throws Exception {
        // Generar par de llaves RSA para el servidor
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        parLlavesServidor = keyGen.generateKeyPair();
        
        // Generar IV aleatorio
        byte[] ivBytes = new byte[16];
        random.nextBytes(ivBytes);
        iv = new IvParameterSpec(ivBytes);
    }

    public static ArrayList<BigInteger> generarParametrosDH() {
        ArrayList<BigInteger> parametros = new ArrayList<>();
        try {
            // Generar parámetros DH usando openssl (simulado aquí)
            BigInteger p = BigInteger.probablePrime(1024, random);
            BigInteger g = BigInteger.valueOf(2); // Generador común
            BigInteger x = new BigInteger(512, random);
            BigInteger gx = g.modPow(x, p);
            
            parametros.add(p);  // índice 0
            parametros.add(g);  // índice 1
            parametros.add(gx); // índice 2
            parametros.add(x);  // índice 3 (exponente privado)
        } catch (Exception e) {
            System.err.println("Error generando parámetros DH: " + e.getMessage());
            e.printStackTrace();
        }
        return parametros;
    }

    public static byte[] firmarParametrosDH(BigInteger g, BigInteger p, BigInteger gx) {
        try {
            // Asegurar que cada representación hexadecimal tenga longitud par
            String gHex = padToEvenLength(g.toString(16));
            String pHex = padToEvenLength(p.toString(16));
            String gxHex = padToEvenLength(gx.toString(16));
            
            String datos = gHex + pHex + gxHex;
    
            // Crear hash SHA-256 de los datos antes de cifrar
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(datos.getBytes());
    
            // Cifrar el hash en lugar de los datos completos
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, parLlavesServidor.getPrivate());
            return rsaCipher.doFinal(hashBytes);
        } catch (Exception e) {
            System.err.println("Error al firmar parámetros DH: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    // Método auxiliar para asegurar longitud par en cadenas hexadecimales
    private static String padToEvenLength(String hex) {
        if (hex.length() % 2 != 0) {
            return "0" + hex;
        }
        return hex;
    }

    public static void establecerLlavesMaestras(BigInteger gy, BigInteger p, BigInteger x) throws Exception {
        // Calcular llave maestra
        BigInteger llaveMaestra = gy.modPow(x, p);
        byte[] llaveMaestraBytes = llaveMaestra.toByteArray();
        
        // Generar llaves de sesión
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(llaveMaestraBytes);
        
        // Primera mitad para cifrado, segunda para HMAC
        llaveEncriptacion = new SecretKeySpec(digest, 0, 32, "AES");
        llaveHmac = new SecretKeySpec(digest, 32, 32, ALGORITMO_HMAC);
    }

    public static byte[] cifrarEstado(int estadoPaquete) throws InvalidAlgorithmParameterException {
        try {
            Cipher cifrador = Cipher.getInstance(ALGORITMO_CIFRADO);
            cifrador.init(Cipher.ENCRYPT_MODE, llaveEncriptacion, iv);
            return cifrador.doFinal(intToBytes(estadoPaquete));
        } catch (Exception e) {
            System.err.println("Error al cifrar el estado: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] firmarEstado(int estadoPaquete, int idUsuario, int idPaquete) {
        try {
            Signature firma = Signature.getInstance(ALGORITMO_FIRMA);
            firma.initSign(parLlavesServidor.getPrivate());
            firma.update(intToBytes(estadoPaquete));
            firma.update(intToBytes(idUsuario));
            firma.update(intToBytes(idPaquete));
            return firma.sign();
        } catch (Exception e) {
            System.err.println("Error al firmar el estado: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public static int[] verificarConsulta(byte[] consultaCifrada, byte[] firma, PublicKey llavePublicaCliente) {
        try {
            // Descifrar la consulta
            Cipher descifrador = Cipher.getInstance(ALGORITMO_CIFRADO);
            descifrador.init(Cipher.DECRYPT_MODE, llaveEncriptacion, iv);
            byte[] consultaDescifrada = descifrador.doFinal(consultaCifrada);
            
            int idUsuario = bytesToInt(new byte[]{
                consultaDescifrada[0], consultaDescifrada[1],
                consultaDescifrada[2], consultaDescifrada[3]
            });
            int idPaquete = bytesToInt(new byte[]{
                consultaDescifrada[4], consultaDescifrada[5],
                consultaDescifrada[6], consultaDescifrada[7]
            });
            
            // Verificar firma
            Signature verificador = Signature.getInstance(ALGORITMO_FIRMA);
            verificador.initVerify(llavePublicaCliente);
            verificador.update(intToBytes(idUsuario));
            verificador.update(intToBytes(idPaquete));
            
            if (verificador.verify(firma)) {
                return new int[]{idUsuario, idPaquete};
            }
        } catch (Exception e) {
            System.err.println("Error al verificar la consulta: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
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
        // BYTES A HEXADECIMAL
        public static String bytesToHex(byte[] bytes) {
            StringBuilder hexString = new StringBuilder();
            for (byte b : bytes) {
                String hex = Integer.toHexString(0xFF & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        }
    
        // HEXADECIMAL A BYTES
        public static byte[] hexToBytes(String hex) {
            int len = hex.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                     + Character.digit(hex.charAt(i+1), 16));
            }
            return data;
        }
}
