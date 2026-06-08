import java.security.MessageDigest;
import java.util.HexFormat;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Hashes {
    int npass = 0;

    public String getSHA512AmbSalt(String pw, String salt) throws Exception{
        String text = salt + pw;
        byte[] bytesText = text.getBytes("UTF-8");
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] bytesHash = digest.digest(bytesText);
        HexFormat hex = HexFormat.of();
        String hash = hex.formatHex(bytesHash);
        return hash;
    }

    public String getPBKDF2AmbSalt(String pw, String salt) throws Exception{
        char[] passwordChars = pw.toCharArray();
        byte[] saltBytes = salt.getBytes("UTF-8");
        PBEKeySpec spec = new PBEKeySpec(passwordChars, saltBytes, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] bytes = factory.generateSecret(spec).getEncoded();
        HexFormat hex = HexFormat.of();
        String hash = hex.formatHex(bytes);
        return hash;
    }

    public String getInterval(long t1, long t2) {
        long diferencia = t2 - t1;
        long millis = diferencia % 1000;
        long totalSegons = diferencia / 1000;
        long segons = totalSegons % 60;
        long totalMinuts = totalSegons/ 60;
        long minuts = totalMinuts % 60;
        long totalHores = totalMinuts / 60;
        long hores = totalHores % 24;
        long dies = totalHores / 24;
        return dies + " dies / " + hores + " hores / " + minuts + " minuts / " + segons + " segons / " + millis + " millis";
    }

    private String comprovaPassword(String prova, String alg, String hash, String salt) throws Exception {
        npass++;
        String hashProva;

        if(alg.equals("SHA-512")) {
            hashProva = getSHA512AmbSalt(prova, salt);
        } else{
            hashProva = getPBKDF2AmbSalt(prova, salt);
        }

        if(hashProva.equals(hash)){
            return prova;
        }
        return null;
    }

    public String forcaBruta(String alg, String hash, String salt) throws Exception{
        npass = 0;
        String charset = "abcdefABCDEF1234567890!";
        char[] password = new char[6];
        String trobat;

        for (int i1 = 0; i1 < charset.length(); i1++) {
            password[0] = charset.charAt(i1);
            for (int i2 = 0; i2 < charset.length(); i2++) {
                password[1] = charset.charAt(i2);
                for (int i3 = 0; i3 < charset.length(); i3++) {
                    password[2] = charset.charAt(i3);
                    for (int i4 = 0; i4 < charset.length(); i4++) {
                        password[3] = charset.charAt(i4);
                        for (int i5 = 0; i5 < charset.length(); i5++) {
                            password[4] = charset.charAt(i5);
                            for (int i6 = 0; i6 < charset.length(); i6++) {
                                password[5] = charset.charAt(i6);
                                String prova = new String(password);
                                trobat = comprovaPassword(prova, alg, hash, salt);
                                if (trobat != null) {
                                    return trobat;
                                }
                            }
                        }
                    }
                }
            }
        }
        return null;
    }
    public static void main(String[] args) throws Exception {
        String salt = "qpoweiruañslkdfjz";
        String pw = "aaabF!";
        Hashes h = new Hashes();
        String[] aHashes = { h.getSHA512AmbSalt(pw, salt),
            h.getPBKDF2AmbSalt(pw, salt) };
        String pwTrobat = null;
        String[] algorismes = {"SHA-512", "PBKDF2"};
        for(int i=0; i< aHashes.length; i++){
            System.out.printf("===============================\n");
            System.out.printf("Algorisme: %s\n", algorismes[i]);
            System.out.printf("Hash: %s\n",aHashes[i]);
            System.out.printf("-------------------------------\n");
            System.out.printf("-- Inici de força bruta ---\n");

            long t1 = System.currentTimeMillis();
            pwTrobat = h.forcaBruta(algorismes[i], aHashes[i], salt);
            long t2 = System.currentTimeMillis();

            System.out.printf("Pass   : %s\n", pwTrobat);
            System.out.printf("Provats: %d\n", h.npass);
            System.out.printf("Temps  : %s\n", h.getInterval(t1, t2));
            System.out.printf("-------------------------------\n\n");
        }
    }
}
