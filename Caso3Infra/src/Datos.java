import java.util.HashMap;
import java.util.Map;

public class Datos {
    
    private static Map<Integer, Integer> usuarios = new HashMap<>();
    private static Map<Integer, Integer> paquetes = new HashMap<>();

    public static void UpdateData() {
        for (int i = 0; i < 32; i++) {
            usuarios.put(i, i);
            paquetes.put(i, i%6);
    }}

    public static Integer ConsultarUsuario(Integer id, Integer paquete) {
        if (usuarios.get(id) != null && usuarios.get(id) == paquete) {
            if (paquetes.get(usuarios.get(id)) != null) {
                return paquetes.get(usuarios.get(id));
            } else {
                return 6;
            }
        } else { 
            return 6;
        } 
            
    }

    public static String ConsultaEstado(Integer estado){
        switch (estado) {
            case 0:
                return "EN OFICINA";
            case 1:
                return "RECOGIDO";
            case 2:
                return "EN CLASIFICACION";
            case 3:
                return "DESPACHADO";
            case 4:
                return "EN ENTREGA";
            case 5:
                return "ENTREGADO";
            default:
                return "DESCONOCIDO";
        }


    }
}
