package com.example.demospringfileupload.controller;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.example.demospringfileupload.crypto.AES;
import com.example.demospringfileupload.crypto.RSA;
import com.example.demospringfileupload.model.DataComplete;
import com.example.demospringfileupload.service.DigitalSignature;
import com.google.common.hash.Hashing;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class CryptController {
    // Mapeo para mostrar la vista de cifrado
    @GetMapping("/encrypt")
    public String encrypt() {
        return "encrypt";
    }

    // Mapeo para mostrar la vista de descifrado
    @GetMapping("/decrypt")
    public String decrypt() {
        return "decrypt";
    }

    // Mapeo para mostrar la vista de cifrado y firma
    @GetMapping("/encrypt_sign")
    public String encryptSign() {
        return "encrypt_sign";
    }

    // Mapeo para mostrar la vista de descifrado y verificación
    @GetMapping("/decrypt_verify")
    public String decryptVerify() {
        return "decrypt_verify";
    }

	// Manejo de la carga de archivos, cifrado y firma
	@PostMapping("/es_upload")
	public String uploadFileEncryptSign(@ModelAttribute("model") DataComplete model, RedirectAttributes attributes) throws Exception
	{
		// Verificación de archivos y entradas
		if(model.getTexto() == null || model.getTexto().isEmpty() ){
			attributes.addFlashAttribute("message", "Por favor seleccione un archivo de texto plano válido.");
			return "redirect:status";
		} else if (model.getClave_simetrica() == null || model.getClave_simetrica().isEmpty()){
			attributes.addFlashAttribute("message", "Por favor seleccione una clave simétrica válida.");
			return "redirect:status";
		} else if (model.getClave_privada() == null || model.getClave_privada().isEmpty()) {
			attributes.addFlashAttribute("message", "Por favor seleccione una clave privada válida.");
			return "redirect:status";
		} else if (model.getClave_publica() == null || model.getClave_publica().isEmpty()) {
			attributes.addFlashAttribute("message", "Por favor seleccione una clave pública válida.");
			return "redirect:status";
		}

		// Creación de la ruta de almacenamiento
		StringBuilder builder = new StringBuilder();
		builder.append("..");
		builder.append(File.separator);
		builder.append("resultados");
		builder.append(File.separator);
		builder.append(model.getTexto().getOriginalFilename().replace(".txt","_OkCifrado.txt"));

        // Firma digital
		String digital_signature = DigitalSignature.sign(model.getTexto(), model.getClave_privada());

        // Cifrado del texto con AES en modo CBC de 128 bits
		final String symmetric_key = new String(model.getClave_simetrica().getBytes(), StandardCharsets.UTF_8);
		String original_string = new String(model.getTexto().getBytes(), StandardCharsets.UTF_8);
		String encrypted_text = AES.encrypt(original_string, symmetric_key);

        // Cifrado de la clave simétrica con RSA
		String sym_key = new String(model.getClave_simetrica().getBytes(), StandardCharsets.UTF_8);

        // Instanciar la clase RSA
		RSA cifrador = new RSA();
		PublicKey public_key = cifrador.getPublic2(model.getClave_publica().getBytes());
		String encrypted_symmetric_key = cifrador.encryptText(sym_key, public_key);

        // Mostrar información sobre los datos cifrados
		System.out.println(digital_signature.length() + " : " + digital_signature);
		System.out.println(encrypted_text.length() + " : " + encrypted_text);
		System.out.println(encrypted_symmetric_key.length() + " : " + encrypted_symmetric_key);
        
		// Combinar los datos cifrados y firmados en un solo archivo
		String file_to_send = digital_signature + encrypted_symmetric_key + encrypted_text;

        // Escribir el archivo resultante
		File archivo = new File(builder.toString());
		BufferedWriter bw;
		bw = new BufferedWriter(new FileWriter(archivo));
		bw.write(file_to_send);
		bw.close();


        // Enviar el estado de la operación y el contenido del archivo
		attributes.addFlashAttribute("message", "Archivo firmado y cifrado correctamente ["+builder.toString()+"]");
		attributes.addFlashAttribute("content", file_to_send);

		return "redirect:/status";
	}

    // Manejo de la carga de archivos, descifrado y verificación
	@PostMapping("/dv_upload")
	public String uploadFileD(@ModelAttribute("model") DataComplete model, RedirectAttributes attributes) throws Exception
	{
		StringBuilder message = new StringBuilder();


        // Verificar la presencia y validez de los archivos y entradas
		if(model.getTexto() == null || model.getTexto().isEmpty() ){
			attributes.addFlashAttribute("message", "Por favor seleccione un archivo de texto plano válido.");
			return "redirect:status";
		} else if (model.getClave_privada() == null || model.getClave_privada().isEmpty()) {
			attributes.addFlashAttribute("message", "Por favor seleccione una clave privada válida.");
			return "redirect:status";
		} else if (model.getClave_publica() == null || model.getClave_publica().isEmpty()) {
			attributes.addFlashAttribute("message", "Por favor seleccione una clave pública válida.");
			return "redirect:status";
		}

        // Crear la ruta de almacenamiento para el archivo descifrado y verificado
		StringBuilder builder = new StringBuilder();
		builder.append("..");
		builder.append(File.separator);
		builder.append("resultados");
		builder.append(File.separator);
		builder.append(model.getTexto().getOriginalFilename().replace(".txt","_OkDescifrado.txt"));

        // Extraer partes del documento completo
		String complete_document = new String(model.getTexto().getBytes(), StandardCharsets.UTF_8);
		String cipher_digital_signature = complete_document.substring(0,172);
		String cipher_symmetric_key = complete_document.substring(172, 344);
		String cipher_text = complete_document.substring(344);

        // Extraer partes del documento completo
		RSA cifrador = new RSA();
		PrivateKey private_key = cifrador.getPrivate2(model.getClave_privada().getBytes());
        // Descifrar la clave simétrica y el texto cifrado
		String decipher_symmetric_key = cifrador.decryptText(cipher_symmetric_key, private_key);
		String decipher_text = null;
        // Calcular el hash para verificar la integridad
		try{
			decipher_text = AES.decrypt(cipher_text, decipher_symmetric_key);
		} catch (Exception e){
			message.append("Fallo servicio de integridad de datos");
		}
		String sha256hex = null;
		try{
			sha256hex = Hashing.sha256().hashString(decipher_text, StandardCharsets.UTF_8).toString();
		}catch (Exception e){
			message.append("Fallo servicio de integridad de datos");
		}

        // Descifrar la firma digital
		PublicKey public_key = cifrador.getPublic2(model.getClave_publica().getBytes());
		String decipher_digital_signature = null;
		try{
			decipher_digital_signature = decipher_digital_signature = cifrador.decryptText(cipher_digital_signature, public_key);
		} catch (Exception e){
			message.append("Fallo servicio de autenticación");
		}

        // Verificación de integridad y autenticidad
		if(decipher_digital_signature != null && decipher_text != null && sha256hex != null) {


			if (decipher_digital_signature.equals(sha256hex)) {
				File archivo = new File(builder.toString());
				BufferedWriter bw;
				bw = new BufferedWriter(new FileWriter(archivo));
				bw.write(decipher_text);
				bw.close();

				message.append("Se descifro y verifo correctamente, archivo almacenado en: ["+builder.toString()+"]");
			}
		}


        // Enviar el estado de la operación y el contenido del archivo
		attributes.addFlashAttribute("message", message.toString());
		attributes.addFlashAttribute("content", decipher_text);
		return "redirect:/status";
	}

    // Mapeo para mostrar la vista de estado
	@GetMapping("/status")
	public String status() {
		return "status";
	}
}
