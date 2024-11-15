import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ThreadServidor extends Thread {
    private Socket sktCliente = null;
    private int id;
    
    public ThreadServidor(Socket pSocket, int pId) {
        this.sktCliente = pSocket;
        this.id = pId;
    }
    
    public void run() {
        System.out.println("Inicio de un nuevo thread: " + id);
        
        try {
            PrintWriter escritor = new PrintWriter(sktCliente.getOutputStream(), true);
            BufferedReader lector = new BufferedReader(new InputStreamReader(sktCliente.getInputStream()));
                
            ProtocoloServidor.procesar(lector, escritor);
            
            escritor.close();
            lector.close();
            sktCliente.close();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        } catch (Exception e) {
                    
                    e.printStackTrace();
                }
    }
}

