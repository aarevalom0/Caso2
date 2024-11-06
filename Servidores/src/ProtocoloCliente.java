import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ProtocoloCliente {
    static PrivateKey clientPrivateKey;
        
    
    
        // Método principal para procesar el protocolo de autenticación y cifrado
        public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut, PublicKey serverPublicKey) 
        throws Exception {
    
            // INICIAR SESION
            pOut.println("SECINIT");
            pOut.flush();
    
            // RETO CIFRADO C(KW+,RETO)
            SecureRandom random = new SecureRandom();
            byte[] reto = new byte[16];
            random.nextBytes(reto);
            serverPublicKey = LlavePublica();
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
            byte[] retoCifrado = rsaCipher.doFinal(reto);
            pOut.println(bytesToHex(retoCifrado));
            pOut.flush();
    
            // VERTIFICAR RESPUESTA
            String respuesta = pIn.readLine();
            if (!respuesta.equals(bytesToHex(retoCifrado))) {
                pOut.println("ERROR");
                pOut.flush();}
            else{pOut.println("ERROR");
            pOut.flush();}
    
            // RECIBE (G, P, G^x) y F
            BigInteger g = new BigInteger(pIn.readLine(), 16);
            BigInteger p = new BigInteger(pIn.readLine(), 16);
            BigInteger g_x = new BigInteger(pIn.readLine(), 16);
            String fHex = pIn.readLine();
            
            // Verificar F usando la llave pública del servidor
            if (!verificarF(serverPublicKey, fHex, g, p, g_x)) {
                pOut.println("ERROR");
                pOut.flush();
            }
            else{
                pOut.println("OK");
                pOut.flush();
                // CALCULAR GY Y ENVIA GY
                DHParameterSpec dhSpec = new DHParameterSpec(p, g);
                KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(1024);
                KeyPair parLlaves = keyGen.generateKeyPair();
                clientPrivateKey = parLlaves.getPrivate();
                keyAgree.init(clientPrivateKey);
                keyAgree.doPhase((Key) g_x, true);
                byte[] sharedSecret = keyAgree.generateSecret();
                pOut.println(bytesToHex(sharedSecret));
                pOut.flush();
                // CALCULAR CLAVE COMPARTIDA
                MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
                byte[] digest = sha512.digest(sharedSecret);
                SecretKey kAB1 = new SecretKeySpec(digest, 0, 32, "AES"); // Para cifrado
                SecretKey kAB2 = new SecretKeySpec(digest, 32, 32, "HmacSHA256");
                String respuesta1 = pIn.readLine();
            if (!respuesta1.equals("TODO BIEN")) {
                pOut.println("POR ACA TAMBIEN");
                pOut.flush();}

    };

        
    }

    public static PublicKey LlavePublica() {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("src\\LlavePublicaServidor\\llave_publica.ser"))) {
            return (PublicKey) ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }




    // VERFIICAR AUTENTICIDAD DDE f
    public static boolean verificarF(PublicKey serverPublicKey, String fHex, BigInteger g, BigInteger p, BigInteger g_x) throws Exception {
        byte[] f = hexToBytes(fHex);
        String datos = g.toString(16) + p.toString(16) + g_x.toString(16);
        byte[] datosBytes = datos.getBytes();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
        byte[] fVerificado = cipher.doFinal(f);
        return MessageDigest.isEqual(fVerificado, datosBytes);
    }

    // Método para enviar mensajes cifrados y autenticados
    public static void enviarMensajeSeguro(String uid, SecretKey kAB1, SecretKey kAB2, PrintWriter pOut, BufferedReader pIn) throws Exception {
        // Cifrar el UID
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, kAB1);
        byte[] uidCifrado = aesCipher.doFinal(uid.getBytes());

        // Generar HMAC del UID cifrado
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(kAB2);
        byte[] uidHMAC = hmac.doFinal(uidCifrado);

        // Enviar UID cifrado y HMAC al servidor
        pOut.println(bytesToHex(uidCifrado));
        pOut.println(bytesToHex(uidHMAC));
        pOut.flush();

        // Esperar y procesar respuesta del servidor
        String respuesta = pIn.readLine();
        System.out.println("Respuesta del servidor: " + respuesta);
    }

    // Método auxiliar para convertir bytes a hexadecimal
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Método auxiliar para convertir hexadecimal a bytes
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
