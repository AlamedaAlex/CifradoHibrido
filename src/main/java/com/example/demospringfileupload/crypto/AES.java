package com.example.demospringfileupload.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class AES {

    private static SecretKeySpec secretKey;
    private static byte[] key;

    private static final String INIT_VECTOR = "RandomInitVector";

    // Configuración de la clave secreta utilizada para encriptar y desencriptar
    public static void setKey(String myKey) {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    // Encripta un texto utilizando el algoritmo AES
    public static String encrypt(String strToEncrypt, String secret) {
        try {
            IvParameterSpec initial_vector = new IvParameterSpec(INIT_VECTOR.getBytes("UTF-8"));

            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, initial_vector);
            // Codifica el texto encriptado en Base64 para que sea seguro de almacenar y transmitir
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println("Error al encriptar: " + e.toString());
        }
        return null;
    }

    // Desencripta un texto encriptado utilizando el algoritmo AES
    public static String decrypt(String strToDecrypt, String secret) {
        try {
            IvParameterSpec initial_vector = new IvParameterSpec(INIT_VECTOR.getBytes("UTF-8"));

            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, initial_vector);
            // Decodifica el texto encriptado en Base64 para obtener el texto original
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error al desencriptar: " + e.toString());
        }
        return null;
    }
}
