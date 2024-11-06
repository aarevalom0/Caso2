
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ProtocoloServidor {
    private static ArrayList<BigInteger> PG;
    private static SecureRandom random = new SecureRandom();
    public static void procesar(BufferedReader pIn, PrintWriter pOut, PrivateKey serverPrivateKey, PublicKey clientPublicKey) 
    throws Exception {

    // Paso 1: Esperar "SECINIT" del cliente
    String mensajeInicial = pIn.readLine();
    if (!"SECINIT".equals(mensajeInicial)) {
        System.out.println("Error: mensaje inicial inválido.");
        return;
    }

    //RECIBIR Y DESCIFREAR RETO D(KW-,RETO)
    String retoCifradoHex = pIn.readLine();
    byte[] retoCifrado = hexToBytes(retoCifradoHex);
    Cipher rsaCipher = Cipher.getInstance("RSA");
    rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
    byte[] reto = rsaCipher.doFinal(retoCifrado);
    pOut.println(bytesToHex(reto));
    pOut.flush();

    //GENERAR PG GX Y ENVIAR F(KW-(GPGX))
    String respuesta = pIn.readLine();
    if (respuesta.equals("OK")) {
        PG = DiffieHellman.GenerateGP();
        BigInteger p=PG.get(0);
        pOut.println(p.toString(16));
        BigInteger g=PG.get(1);
        pOut.println(g.toString(16));
        BigInteger x = new BigInteger(512, random);
        BigInteger g_x = g.modPow(x, p);
        String datos = g.toString(16) + p.toString(16) + g_x.toString(16);
        byte[] datosBytes = datos.getBytes();
        Cipher signCipher = Cipher.getInstance("RSA");
        signCipher.init(Cipher.ENCRYPT_MODE, serverPrivateKey);
        byte[] f = signCipher.doFinal(datosBytes);
        pOut.println(g_x.toString(16));
        pOut.println(bytesToHex(f));
        pOut.flush();
        String respuesta1 = pIn.readLine();
    if (respuesta1.equals("OK")) {

        //RECIBIR GY Y CALCULAR CLAVE COMPARTIDA
        String g_yHex = pIn.readLine();
        BigInteger g_y = new BigInteger(g_yHex, 16);
        BigInteger sharedSecret = g_y.modPow(x, p);
        byte[] sharedSecretBytes = sharedSecret.toByteArray();
        // CALCULAR CLAVE COMPARTIDA
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecretBytes);
        SecretKey kAB1 = new SecretKeySpec(digest, 0, 32, "AES"); // Para cifrado
        SecretKey kAB2 = new SecretKeySpec(digest, 32, 32, "HmacSHA256");
        pOut.println("TODO BIEN");
        pOut.flush();
    }

    }}

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
