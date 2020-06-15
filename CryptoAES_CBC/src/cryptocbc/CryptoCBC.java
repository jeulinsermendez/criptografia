package cryptocbc;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author SOLUCIO
 */

public class CryptoCBC {

    public static final byte[] IV_PARAM = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
        CryptoCBC app = new CryptoCBC();
        app.run();
    }

    private void run() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
        Scanner scan = new Scanner (System.in);
        System.out.println("Primer introdueix TOKEN per crear la Clau Secreta:");
        String key = scan.nextLine();
        SecretKey sKey = passwordKeyGeneration(key,256);
        System.out.println("La clau secreta generada és: " + sKey);
        System.out.println("Introdueix text a xifrar: ");
        String msg= scan.nextLine();
        byte[] data = msg.getBytes();
        byte[] encripted = Encript(sKey, data);
        String textXifrat = readByte(encripted);
        System.out.println("Text xifrat: " + textXifrat);
        byte[] decripted = Decript(sKey, encripted);
        String textDesxifrat = readByte(decripted);
        System.out.println("Texto desxifrat: " + textDesxifrat);
    }

    private byte[] Encript(SecretKey sKey, byte[] data) 
    {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(IV_PARAM);
            cipher.init(Cipher.ENCRYPT_MODE, sKey, iv);
            encryptedData = cipher.doFinal(data);
        } catch (Exception ex) {
            System.err.println("Error xifrant les dades: " + ex);    
        }
        return encryptedData;
    }

    private byte[] Decript(SecretKey sKey, byte[] dataEncripted) 
    {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(IV_PARAM);
            cipher.init(Cipher.DECRYPT_MODE, sKey, iv);
            decryptedData = cipher.doFinal(dataEncripted);
        } catch (Exception ex) {
            System.err.println("Error desxifrant les dades: " + ex);
        }    
        return decryptedData;
    }

    public SecretKey passwordKeyGeneration(String text,int keySize) {

        SecretKey sKey = null;

        if ((keySize == 128) || (keySize == 192) || (keySize == 256)) {

            try {
                
                byte[] data = text.getBytes("UTF-8");
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] hash = md.digest(data);
                byte[] key = Arrays.copyOf(hash, keySize / 8);
                sKey = new SecretKeySpec(key, "AES");
                
            } catch (Exception ex) {

                System.err.println("Error generant la clau: " + ex);

            }

        }

        return sKey;

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
