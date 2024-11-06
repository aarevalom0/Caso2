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

                    byte[] IdCifrado = Base64.getDecoder().decode(pIn.readLine());
                    byte[] HmacRecibido = Base64.getDecoder().decode(pIn.readLine());
                    String Id = new String(Seguridad.descifrarSimetrico(K_AB1, IdCifrado,iv));
                    byte[] Hmac = Seguridad.HMAC(K_AB2, IdCifrado);

                    byte[] IDPaqC = Base64.getDecoder().decode(pIn.readLine());
                    byte[] HMACPaq = Base64.getDecoder().decode(pIn.readLine());
                    String Idp = new String(Seguridad.descifrarSimetrico(K_AB1, IDPaqC,iv));
                    byte[] HmacPaq = Seguridad.HMAC(K_AB2, IDPaqC);

                    if (Base64.getEncoder().encodeToString(HmacRecibido).equals(Base64.getEncoder().encodeToString(Hmac))) {
                        if (Base64.getEncoder().encodeToString(HMACPaq).equals(Base64.getEncoder().encodeToString(HmacPaq))) {

                            Integer estado = Datos.ConsultarUsuario(Integer.parseInt(Id), Integer.parseInt(Idp));
                            String Estadocifrado = Base64.getEncoder().encodeToString(Seguridad.cifrarSimetrico(K_AB1, estado.toString(), iv));
                            pOut.println(Estadocifrado);
                            byte[] HMACEstado = Seguridad.HMAC(K_AB2, Base64.getDecoder().decode(Estadocifrado));
                            pOut.println(Base64.getEncoder().encodeToString(HMACEstado));

                        }  else {
                    pOut.println("ERROR");
                    System.out.println("Error en la consulta");
                }                       
                    } else {
                        pOut.println("ERROR");
                        System.out.println("Error en la consulta");
                    } 
                } else {
                    pOut.println("ERROR");
                    System.out.println("Error en la consulta");
                }
                


            } else {
                pOut.println("ERROR");
                System.out.println("Error en la consulta");
            }
        } else {
            pOut.println("ERROR");
            System.out.println("Error en la consulta");
        } 

       
    }
}

    