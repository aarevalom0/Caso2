import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.Key;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ProtocoloServidor {
    private Socket sockCliente;
    
    
    public ProtocoloServidor(Socket s) {
        this.sockCliente = s;
    try {
        PrintWriter escritor = new PrintWriter(sockCliente.getOutputStream(), true);
        BufferedReader lector = new BufferedReader(new InputStreamReader(sockCliente.getInputStream()));
    } catch (IOException e) {
        e.printStackTrace();
    }
    }

    public static void procesar(BufferedReader pIn, PrintWriter pOut) throws Exception {
        //Inicia conversacion
        String inputLine, outputLine;
        // Valida SECINIT y descifra el reto
        inputLine = pIn.readLine();
        if (inputLine.equals("SECINIT")) {
            // tiempo inicial
            String reto = pIn.readLine();
            byte[] retoCifrado = Base64.getDecoder().decode(reto);
            byte[] retoDescifrado = Seguridad.descifrar(Seguridad.LlavePrivadaServidor(), retoCifrado);
            // tiempo final sumar a variable estatica tiempo
            String retoDescifradoStr = new String(retoDescifrado);
            pOut.println(retoDescifradoStr);
            inputLine = pIn.readLine();
            // Continua la conversacion envia G P Gx F(K_w-,(G,P,Gx))
            if (inputLine.equals("OK")) {
                // tiempo 1
                ArrayList<BigInteger> PG = DiffieHellman.GenerateGP();
                BigInteger P = PG.get(0);
                BigInteger G = PG.get(1);
                BigInteger X = PG.get(2);
                BigInteger Gx = PG.get(3);
                // tiempo 2
                pOut.println(P.toString(16));
                pOut.println(G.toString(16));
                pOut.println(Gx.toString(16));
                byte[] F = Seguridad.Firmar( (P.toString(16) + G.toString(16) + Gx.toString(16)).getBytes());
                pOut.println(Base64.getEncoder().encodeToString(F));
                inputLine = pIn.readLine();
                if (inputLine.equals("OK")) {
                    BigInteger Gy = new BigInteger(pIn.readLine(), 16);
                    byte[] iv = Seguridad.GenerarIV();
                    pOut.println(Base64.getEncoder().encodeToString(iv));
                    BigInteger Secreto = Gy.modPow(X, P);
                    ArrayList<Key> llaves = Seguridad.LlavesSimetricas(Secreto);
                    Key K_AB1 = llaves.get(0);
                    Key K_AB2 = llaves.get(1);
                    
                } else {
                    pOut.println("ERROR");
                }
                


            } else {
                pOut.println("ERROR");
            }
        } 

       
    }
}

    