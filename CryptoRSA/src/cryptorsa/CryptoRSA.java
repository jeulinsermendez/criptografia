
package cryptorsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 *
 * @author SOLUCIÓ
 */
public class CryptoRSA {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        CryptoRSA app = new CryptoRSA();
        app.run();
    }

    private void run() {
        //Clau asimètrica
        System.out.println("Primer generem la clau asimètrica RSA");
        KeyPair key = generarClauRSA(2048);
        PublicKey pubKey = key.getPublic();
        System.out.println("La clau pública amb la que xifrarem la clau simètrica és: " + pubKey);
        PrivateKey privKey = key.getPrivate();
        System.out.println("La clau privada amb la que desxifrarem la clau simètrica és: " + privKey);
        
        //Clau simètrica
        SecretKey sKey = generarClauSecreta();
        System.out.println("La clau secreta generada és: " + sKey);
                
        //Text a xifrar
        Scanner scan = new Scanner (System.in);
        System.out.println("Introdueix text a xifrar: ");
        String msg= scan.nextLine();
        byte[] data = msg.getBytes();
        
        //Text xifrat
        byte[][] dataEncripted = encryptWrapper(data,pubKey, sKey);     
                
        //Text desxifrat
        byte[] dataDecripted = DecryptWrapper(dataEncripted, privKey);
        if (dataDecripted != null) {
            String textDesxifrat = readByte(dataDecripted);
            System.out.println("Texto desxifrat: " + textDesxifrat);
        } else{
            System.out.println("Error desxifrant");
        }
                
    }

    public KeyPair generarClauRSA(int len) {

        KeyPair keys = null;

        try {

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    private SecretKey generarClauSecreta() {
        KeyGenerator kgen;
        SecretKey sKey;
        try {
            kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            sKey = kgen.generateKey();
        } catch (NoSuchAlgorithmException ex) {
            sKey = null;
            System.out.println("Error al generar la clau secreta");
        }
        return sKey;
    }
    
    public byte[][] encryptWrapper(byte[] data, PublicKey pub, SecretKey sKey) {
        byte[][] encryptedWrapper = new byte[2][];
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            byte[] encMsg = cipher.doFinal(data);
            String textXifrat = readByte(encMsg);
            System.out.println("Text xifrat: " + textXifrat);
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, pub);
            byte[] encKey = cipher.wrap(sKey);
            encryptedWrapper[0] = encMsg;
            encryptedWrapper[1] = encKey;
        } catch (Exception ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return encryptedWrapper;

    }
    
    public byte[] DecryptWrapper(byte[][] wrapped, PrivateKey priv) {
        byte[] data;
        try {
            Cipher cipher;
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.UNWRAP_MODE, priv);
            SecretKey sKey = (SecretKey) cipher.unwrap(wrapped[1], "AES", cipher.SECRET_KEY);
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, sKey);
            data = cipher.doFinal(wrapped[0]);
        } catch (Exception ex) {
            data = null;
            System.err.println("Error desxifrant: " + ex);
        }
        return data;

    }
    private String readByte(byte[] encripted) {
        String a = "";
        for (int i = 0; i < encripted.length; i++) {
            char c = (char) encripted[i];
            a += c;
        }
        return a;
    }

}
