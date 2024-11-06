import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.math.BigInteger;

public class DiffieHellman {

    private static ArrayList<BigInteger> PG;
        public static ArrayList<BigInteger> GenerateGP(){
            try {
            PG = new ArrayList<BigInteger>();
            String opensslPath = "src\\OpenSSL-1.1.1h_win32\\openssl.exe";
            ProcessBuilder processBuilder = new ProcessBuilder(opensslPath, "dhparam", "-text", "1024");
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                String p = extraerPrime(output.toString());
                String g = extraerGenerator(output.toString());
                BigInteger pDecimal = new BigInteger(p, 16);
                BigInteger gDecimal = new BigInteger(g, 16);
                PG.add(pDecimal);
                PG.add(gDecimal);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return PG;
    }
    private static String extraerPrime(String output) {
        Pattern primePattern = Pattern.compile("prime:\\s*([0-9a-fA-F:\\s]+)");
        Matcher matcher = primePattern.matcher(output);
        if (matcher.find()) {
            return matcher.group(1).replaceAll("\\s|:", "");
        }
        return null;
    }

    private static String extraerGenerator(String output) {
        Pattern generatorPattern = Pattern.compile("generator:\\s*(\\d+)");
        Matcher matcher = generatorPattern.matcher(output);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
    
}
