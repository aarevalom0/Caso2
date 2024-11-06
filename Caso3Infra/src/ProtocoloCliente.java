import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.SecretKey;

public class ProtocoloCliente {
    private InputStream inputStream;
    private OutputStream outputStream;

  
    public static void procesar(BufferedReader pIn, PrintWriter pOut) throws Exception {
        SecureRandom random = new SecureRandom();
        String inputLine, outputLine;
        Key publicaservidor =  Seguridad.LlavePublicaServidor();
        //Inicia conversacion
        //1. Envia SECINIT y el reto cifrado
        pOut.println("SECINIT");
        
        byte[] reto = new byte[16];
        random.nextBytes(reto);
        String retoBase64 = Base64.getEncoder().encodeToString(reto);
        String retoCifradoBase64 = Base64.getEncoder().encodeToString(Seguridad.cifrar(publicaservidor, retoBase64));
        pOut.println(retoCifradoBase64);
        inputLine = pIn.readLine();
        if(inputLine.equals(retoBase64)) {
            pOut.println("OK");
            //Recibe G P Gx F(K_w-,(G,P,Gx))
            BigInteger P = new BigInteger(pIn.readLine(), 16);
            BigInteger G = new BigInteger(pIn.readLine(), 16);
            BigInteger Gx = new BigInteger(pIn.readLine(), 16);
            byte[] F = Base64.getDecoder().decode(pIn.readLine());
            if(Seguridad.VerificaFirma((P.toString(16) + G.toString(16) + Gx.toString(16)).getBytes(),F)) {
                pOut.println("OK");
                BigInteger Gy = Seguridad.GenerarPrimo( P, G);
                pOut.println(Gy.toString(16));
                byte[] iv = Base64.getDecoder().decode(pIn.readLine());
                System.out.println("IV: " + Base64.getEncoder().encodeToString(iv));

                } 
            else {
            pOut.println("ERROR");
                        }
                }
        else {
            pOut.println("ERROR");
                        }

        }
}
        
        
        

       