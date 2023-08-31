package com.example.demospringfileupload.crypto;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

public class Keys {
    private static final String algoritmo = "RSA";
    private KeyPairGenerator generadorLlaves;
    private KeyPair llavesAsimetricas;
    private PrivateKey llavePrivada;
    private PublicKey llavePublica;

    // Constructor que inicializa el generador de llaves asimétricas con el tamaño especificado
    public Keys(int keySize) throws NoSuchAlgorithmException {
        this.generadorLlaves = KeyPairGenerator.getInstance(algoritmo);

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(4);   // algo específico del dispositivo se utilizará para establecer esto

        this.generadorLlaves.initialize(keySize, random);
    }

    // Genera un par de llaves público-privado
    public void createKeys() {
        this.llavesAsimetricas = this.generadorLlaves.generateKeyPair();
        this.llavePrivada = llavesAsimetricas.getPrivate();
        this.llavePublica = llavesAsimetricas.getPublic();
    }

    // Crea un archivo para almacenar la llave
    public static void crearArchivoLLave(String path, byte[] llave) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(llave);
        fos.flush();
        fos.close();
    }

    // Métodos getter y setter para la llave privada
    public PrivateKey getLlavePrivada() {
        return llavePrivada;
    }

    public void setLlavePrivada(PrivateKey llavePrivada) {
        this.llavePrivada = llavePrivada;
    }

    // Métodos getter y setter para la llave pública
    public PublicKey getLlavePublica() {
        return llavePublica;
    }

    public void setLlavePublica(PublicKey llavePublica) {
        this.llavePublica = llavePublica;
    }
}

