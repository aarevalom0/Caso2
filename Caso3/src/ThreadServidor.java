import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class ThreadServidor implements Runnable {
    private Socket socket;
    private static final Map<Integer, Map<Integer, Integer>> TABLA_ESTADOS = new HashMap<>();
    private PublicKey llavePublicaCliente;
    
    // Estados posibles de los paquetes
    public static final int ENOFICINA = 1;
    public static final int RECOGIDO = 2;
    public static final int ENCLASIFICACION = 3;
    public static final int DESPACHADO = 4;
    public static final int ENENTREGA = 5;
    public static final int ENTREGADO = 6;
    public static final int DESCONOCIDO = 7;

    static {
        // Inicializar tabla de estados con datos de prueba
        // Usuario 1
        Map<Integer, Integer> paquetesUsuario1 = new HashMap<>();
        paquetesUsuario1.put(101, ENOFICINA);
        paquetesUsuario1.put(102, RECOGIDO);
        paquetesUsuario1.put(103, ENTREGADO);
        TABLA_ESTADOS.put(1, paquetesUsuario1);

        // Usuario 2
        Map<Integer, Integer> paquetesUsuario2 = new HashMap<>();
        paquetesUsuario2.put(201, ENCLASIFICACION);
        paquetesUsuario2.put(202, DESPACHADO);
        TABLA_ESTADOS.put(2, paquetesUsuario2);
        
        // Agregar más usuarios y paquetes según sea necesario
    }

    public ThreadServidor(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try (DataInputStream in = new DataInputStream(socket.getInputStream());
             DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
            // 2. Generar y enviar parámetros DH
            var parametrosDH = ProtocoloServidor.generarParametrosDH();
            BigInteger p = parametrosDH.get(0);
            BigInteger g = parametrosDH.get(1);
            BigInteger gx = parametrosDH.get(2);
            BigInteger x = parametrosDH.get(3);
             // 3. Firmar y enviar parámetros DH
             byte[] firmaDH = ProtocoloServidor.firmarParametrosDH(g, p, gx);
            
             // Enviar parámetros DH y firma
             ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             oos.writeObject(p);
             oos.writeObject(g);
             oos.writeObject(gx);
             oos.writeObject(firmaDH);
            // 1. Recibir llave pública del cliente
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            llavePublicaCliente = (PublicKey) ois.readObject();

            

           

            // 4. Recibir gy del cliente
            BigInteger gy = (BigInteger) ois.readObject();

            // 5. Establecer llaves maestras
            ProtocoloServidor.establecerLlavesMaestras(gy, p, x);

            // 6. Recibir consulta cifrada y firma
            byte[] consultaCifrada = new byte[in.readInt()];
            in.readFully(consultaCifrada);
            byte[] firmaConsulta = new byte[in.readInt()];
            in.readFully(firmaConsulta);

            // 7. Verificar consulta
            int[] datosConsulta = ProtocoloServidor.verificarConsulta(consultaCifrada, firmaConsulta, llavePublicaCliente);
            
            if (datosConsulta != null) {
                int idUsuario = datosConsulta[0];
                int idPaquete = datosConsulta[1];

                // 8. Buscar estado del paquete
                int estado = buscarEstado(idUsuario, idPaquete);

                // 9. Cifrar y firmar respuesta
                byte[] estadoCifrado = ProtocoloServidor.cifrarEstado(estado);
                byte[] firmaEstado = ProtocoloServidor.firmarEstado(estado, idUsuario, idPaquete);

                // 10. Enviar respuesta cifrada y firma
                out.writeInt(estadoCifrado.length);
                out.write(estadoCifrado);
                out.writeInt(firmaEstado.length);
                out.write(firmaEstado);
            } else {
                // Enviar error
                out.writeInt(DESCONOCIDO);
            }

        } catch (Exception e) {
            System.err.println("Error en el servidor delegado: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                System.err.println("Error cerrando el socket: " + e.getMessage());
            }
        }
    }

    private int buscarEstado(int idUsuario, int idPaquete) {
        Map<Integer, Integer> paquetesUsuario = TABLA_ESTADOS.get(idUsuario);
        if (paquetesUsuario != null) {
            return paquetesUsuario.getOrDefault(idPaquete, DESCONOCIDO);
        }
        return DESCONOCIDO;
    }

    public static String obtenerEstadoTexto(int estado) {
        switch (estado) {
            case ENOFICINA: return "EN OFICINA";
            case RECOGIDO: return "RECOGIDO";
            case ENCLASIFICACION: return "EN CLASIFICACION";
            case DESPACHADO: return "DESPACHADO";
            case ENENTREGA: return "EN ENTREGA";
            case ENTREGADO: return "ENTREGADO";
            default: return "DESCONOCIDO";
        }
    }
}