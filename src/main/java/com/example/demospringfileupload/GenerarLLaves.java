package com.example.demospringfileupload;

import com.example.demospringfileupload.crypto.Keys;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static com.example.demospringfileupload.crypto.Keys.crearArchivoLLave;

public class GenerarLLaves {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
        // Indicadores para generar claves simétricas y asimétricas
        Boolean generate_symmetric_key = Boolean.TRUE;
        Boolean generate_asymmetric_key = Boolean.TRUE;

        // Directorio para almacenar las claves generadas
        StringBuilder path_directory = new StringBuilder();
        path_directory.append("..");
        path_directory.append(File.separator);
        path_directory.append("Keys");
        path_directory.append(File.separator);

        // Generación de clave simétrica AES
        if(generate_symmetric_key){
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128); // por ejemplo
            SecretKey secretKey = keyGen.generateKey();

            // Crear archivo de clave simétrica
            crearArchivoLLave("../LLave/LLaveSimetrica.txt", secretKey.getEncoded());
            System.out.println("Clave simétrica generada");
        }

        // Generación de claves asimétricas RSA
        if(generate_asymmetric_key){
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

            generator.initialize(1024, random);

            KeyPair pair = generator.generateKeyPair();
            RSAPrivateKey priv = (RSAPrivateKey) pair.getPrivate();
            RSAPublicKey pub = (RSAPublicKey) pair.getPublic();

            // Crear archivos de claves privada y pública
            crearArchivoLLave("../LLave/LLavePrivada.txt", priv.getEncoded());
            crearArchivoLLave("../LLave/LLavePublica.txt", pub.getEncoded());
            System.out.println("Clave privada generada");
            System.out.println("Clave pública generada");
        }
    }
}

