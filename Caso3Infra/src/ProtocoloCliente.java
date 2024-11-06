import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.SecretKey;

public class ProtocoloCliente {
    private InputStream inputStream;
    private OutputStream outputStream;

  
    public static void procesar(BufferedReader pIn, PrintWriter pOut, Integer id, Integer IdP) throws Exception {
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
                BigInteger Y = Seguridad.GenerarPrimo( P, G);
                BigInteger Gy = G.modPow(Y, P);
                pOut.println(Gy.toString(16));
                BigInteger Secreto = Gx.modPow(Y, P);
                byte[] iv = Base64.getDecoder().decode(pIn.readLine());
                ArrayList<Key> llaves = Seguridad.LlavesSimetricas(Secreto);
                Key K_AB1 = llaves.get(0);
                Key K_AB2 = llaves.get(1);
                String IdCifrado = Base64.getEncoder().encodeToString(Seguridad.cifrarSimetrico(K_AB1, id.toString(), iv));
                pOut.println(IdCifrado);
                byte[] Hmac = Seguridad.HMAC(K_AB2, Base64.getDecoder().decode(IdCifrado));
                pOut.println(Base64.getEncoder().encodeToString(Hmac));

                String IdPaq = Base64.getEncoder().encodeToString(Seguridad.cifrarSimetrico(K_AB1, IdP.toString(), iv));
                pOut.println(IdPaq);
                byte[] HmacPaq = Seguridad.HMAC(K_AB2, Base64.getDecoder().decode(IdPaq));
                pOut.println(Base64.getEncoder().encodeToString(HmacPaq));

                //System.out.println("ID: " + id + " IDP: " + IdP);

                byte[] Estado = Base64.getDecoder().decode(pIn.readLine());
                byte[] HMACEstado = Base64.getDecoder().decode(pIn.readLine());
                String EstadoDescifrado = new String(Seguridad.descifrarSimetrico(K_AB1, Estado,iv));
                byte[] HMACCalculado = Seguridad.HMAC(K_AB2, Estado);

                if(Base64.getEncoder().encodeToString(HMACCalculado).equals(Base64.getEncoder().encodeToString(HMACEstado))) {
                        String respuesta = Datos.ConsultaEstado(Integer.parseInt(EstadoDescifrado));
                        System.out.println("El paquete del usuario " + id + " con Identificador de paquete " + IdP + " tiene estado: " + respuesta);
                        pOut.println("TERMINAR");
                    }else {
                        pOut.println("ERROR");
                        System.out.println("Error en la consulta");
                    }         
                }else {
                    pOut.println("ERROR");
                    System.out.println("Error en la consulta");
                }
        

        }else {
            pOut.println("ERROR");
            System.out.println("Error en la consulta");
        }
}

}
        
        
        

       
