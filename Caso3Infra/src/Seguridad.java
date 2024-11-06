import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class Seguridad {

    private static final String PADDING = "AES/ECB/PKCS5Padding";
    private static final String RUTA_LLAVE_PRIVADA = "servidor_privada.key";
    private static final String RUTA_LLAVE_PUBLICA = "servidor_publica.key";
    private static final String ALGORITMO_RSA = "RSA/ECB/PKCS1Padding";
    private static final String FIRMA = "SHA1withRSA";
    private static final SecureRandom random = new SecureRandom();

    public static byte[] cifrar(Key llave, String texto) {
    byte[] textoCifrado;
    try {
        Cipher cifrador = Cipher.getInstance(ALGORITMO_RSA);
        byte[] textoClaro = texto.getBytes();
        cifrador.init(Cipher.ENCRYPT_MODE, llave);
        textoCifrado = cifrador.doFinal(textoClaro);
        return textoCifrado;
    } catch (Exception e) {
        System.out.println("Excepcion: " + e.getMessage());
        return null;
    }
    }

    public static byte[] descifrar(Key llave, byte[] texto) {
        byte[] textoClaro;
        try {
            Cipher cifrador = Cipher.getInstance(ALGORITMO_RSA);
            cifrador.init(Cipher.DECRYPT_MODE, llave);
            textoClaro = cifrador.doFinal(texto);
            return textoClaro;
        } catch (Exception e) {
            System.out.println("Excepcion: " + e.getMessage());
            return null;
        }
    }

    public static String Digest(String algorithm, byte[] buffer) {
    try {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        digest.update(buffer);
        byte[] resultado = digest.digest();
        String out = "";
        for (int i = 0; i < resultado.length; i++) {
            if ((resultado[i] & 0xff) <= 0xf) {
                out += "0";
            }
            out += Integer.toHexString(resultado[i] & 0xff).toLowerCase();
        }
        return out;
    } catch (Exception e) {
        System.out.println("Error al calcular el digest: " + e.getMessage());
        return null;
    }
    }

    public static void NuevasLlaves() throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        KeyPairGenerator Parllaves= KeyPairGenerator.getInstance("RSA");
        Parllaves.initialize(1024);
        KeyPair llaves = Parllaves.generateKeyPair();
        try (ObjectOutputStream oos = new ObjectOutputStream(
                    new FileOutputStream(RUTA_LLAVE_PRIVADA))) {
                oos.writeObject((Key)  llaves.getPrivate());
                oos.close();
            }
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(RUTA_LLAVE_PUBLICA))) {
            oos.writeObject((Key) llaves.getPublic());
            oos.close();
        }
        
    }

    public static Key LlavePublicaServidor() throws FileNotFoundException, IOException, ClassNotFoundException {
        InputStream archivo = new FileInputStream(RUTA_LLAVE_PUBLICA);
        ObjectInputStream ois = new ObjectInputStream(archivo);
        Key llave = (Key) ois.readObject();
        ois.close();
        archivo.close();
        return llave;
    }

    public static Key LlavePrivadaServidor() throws IOException, ClassNotFoundException {
        InputStream archivo = new FileInputStream(RUTA_LLAVE_PRIVADA);
        ObjectInputStream ois = new ObjectInputStream(archivo);
        Key llave = (Key) ois.readObject();
        ois.close();
        archivo.close();
        return llave;
    }

    public static byte[] Firmar(byte[] texto) throws Exception {
        Signature firma = Signature.getInstance(FIRMA);
        firma.initSign((PrivateKey) LlavePrivadaServidor());
        firma.update(texto);
        return firma.sign();
    }

    public static boolean VerificaFirma(byte[] texto, byte[] firma) throws Exception {
        Signature valida = Signature.getInstance(FIRMA);
        valida.initVerify((PublicKey) LlavePublicaServidor());
        valida.update(texto);
        return valida.verify(firma);
    }

    public static BigInteger GenerarPrimo(BigInteger p, BigInteger g) {
        BigInteger x = new BigInteger(1024, random);
        while(x.compareTo(p) >= 0){
            x = new BigInteger(1024, random);
        }

        BigInteger Gx = g.modPow(x, p);
        return Gx;
    }

    public static byte[] GenerarIV() {
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return iv;
    }




}