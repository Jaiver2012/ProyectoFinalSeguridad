package cliente;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

public class Cliente {

	//Datos conexión
	
	private int port=9000;
	private String ip="localhost";
	private Socket client;
	private DataInputStream dataInputOne;
    private DataOutputStream dataOutputOne;
    private DataOutputStream pathFile;
    private String[] mensajeRecibido;
    private Scanner teclado;
    
    private SecretKeySpec claveAES;
    
    //recibir archivo
    BufferedInputStream bis;
    BufferedOutputStream bos;
    int in;
    byte[] byteArray;
    //Fichero a transferir
     String fileName = "";
    
    
    //Datos para el intercambio de claves  (diffie-hellman)
	
    private PrivateKey privateKey;
    private PublicKey  publicKey;
    private PublicKey  receivedPublicKey;
    private byte[]     secretKey;
    private String     secretMessage;
	
	
    /**
     * 
     * @param args
     */
	public static void main(String[] args) {
		Cliente newClient = new Cliente();
		newClient.generateKeys();
		newClient.initClient();
	}
	
	/**
	 * 
	 */
	private void initClient() {
		
		teclado = new Scanner(System.in);
        try{
            System.out.println("---------------------------------------------------------------------------------------------------------");
            System.out.println("Escriba la ruta del archivo para iniciar la ejecución. Si desea salir del programa escriba 'exit'.");
            fileName = teclado.nextLine();
            while(!fileName.equals("exit") && !fileName.contentEquals("")){
            	
            	System.out.println("Creando conexión con el servidor en "+ ip +":"+port+"...");
            	client= new Socket(ip,port);
            	System.out.println("¡Conexión exitosa!");
            	
            	dataOutputOne = new DataOutputStream(client.getOutputStream());
            	dataInputOne = new DataInputStream(client.getInputStream());
            	

            		//convertir publicKey del cliente a byte            
            		byte[] byte_pubkey = publicKey.getEncoded();

            		//convertir byte a String 
            		String publicKeyString = Base64.getEncoder().encodeToString(byte_pubkey);

            		//Enviamos la publickey convertida en string al servidor

            		dataOutputOne.writeUTF("1-" + publicKeyString+"-"+fileName);



            		mensajeRecibido = dataInputOne.readUTF().split("-");

            		if(mensajeRecibido[0].equals("1")) {
            			//Recibimos la clave publica del cliente
            			receivePublicKeyFrom(mensajeRecibido[1]);
            			generateCommonSecretKey();

            			// Hasta aqui lo que se ha hecho es generar una clave secreta en común
            			System.out.println("Clave secreta en común en el cliente: " + Base64.getEncoder().encodeToString(secretKey));

            		}

            		

            		//-----------------------------------------------------------------------------------------------------------------------------
            		// Send file to server
            		//-----------------------------------------------------------------------------------------------------------------------------
            		sendFile();


            		//-----------------------------------------------------------------------------------------------------------------------------
            		// Run again
            		//-----------------------------------------------------------------------------------------------------------------------------
            		
            		System.out.println("---------------------------------------------------------------------------------------------------------");
            		System.out.println("Escriba la ruta del archivo para iniciar la ejecución. Si desea salir del programa escriba 'exit'.");
            		fileName = teclado.nextLine();
            	
            }
            System.out.println("---------------------------------------------------------------------------------------------------------");
            System.out.println("PROGRAMA TERMINADO.");
            client.close();
        }catch(Exception e){

        }
	}
	
	/**
	 * 
	 * @param nombreArchivo
	 * @return
	 * @throws Exception
	 */
	public static byte[] obtenerChecksum(String nombreArchivo) throws Exception {
        InputStream fis = new FileInputStream(nombreArchivo);

        byte[] buffer = new byte[1024];
        MessageDigest complete = MessageDigest.getInstance("SHA-1");
        int numRead;
        // Leer el archivo pedazo por pedazo
        do {
            // Leer datos y ponerlos dentro del búfer
            numRead = fis.read(buffer);
            // Si se leyó algo, se actualiza el MessageDigest
            if (numRead > 0) {
                complete.update(buffer, 0, numRead);
            }
        } while (numRead != -1);

        fis.close();
        // Devolver el arreglo de bytes
        return complete.digest();
    }

	/**
	 * 
	 * @param nombreArchivo
	 * @return
	 * @throws Exception
	 */
    public static String obtenerHASHComoString(String nombreArchivo) throws Exception {
        // Convertir el arreglo de bytes a cadena
        byte[] b = obtenerChecksum(nombreArchivo);
        StringBuilder resultado = new StringBuilder();

        for (byte unByte : b) {
            resultado.append(Integer.toString((unByte & 0xff) + 0x100, 16).substring(1));
        }
        System.out.println("Hash desde el cliente");
        System.out.println(resultado.toString());
        return resultado.toString();
    }
	
	/**
	 * 
	 */
	public void sendFile() {
		
		try {

			 System.out.println("Enviando archivo al servidor...");
             final File localFile = new File( fileName );
             BufferedInputStream  bis = new BufferedInputStream(new FileInputStream(localFile));
             BufferedOutputStream bos = new BufferedOutputStream(client.getOutputStream());
             //Send name of file
             dataOutputOne =new DataOutputStream(client.getOutputStream());
             //prueba de encriptación con AES
             dataOutputOne.writeUTF(encriptar(localFile.getName()));
             //Send file
             byteArray = new byte[8192];
             while ((in = bis.read(byteArray)) != -1){
             	bos.write(byteArray,0,in);
             }
             System.out.println("Archivo enviado exitosamente");
             obtenerHASHComoString(fileName);
             bis.close();
             bos.close();

			
			
		}catch (Exception e) {
			// TODO: handle exception
			System.out.println(e);
		}
	}
	
	private void crearClave() throws Exception {
        byte[] claveEncriptacion = secretKey;
         
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        claveEncriptacion = sha.digest(claveEncriptacion);
        claveEncriptacion = Arrays.copyOf(claveEncriptacion, 16);
         
        SecretKeySpec secretKey = new SecretKeySpec(claveEncriptacion, "AES");
 
        claveAES = secretKey;
    }

	public String encriptar(String mensaje) throws Exception {
        crearClave();
         
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");        
        cipher.init(Cipher.ENCRYPT_MODE, claveAES);
 
        byte[] datosEncriptar = mensaje.getBytes("UTF-8");
        byte[] bytesEncriptados = cipher.doFinal(datosEncriptar);
        String encriptado = Base64.getEncoder().encodeToString(bytesEncriptados);
        
        return encriptado;
    }

	/**
	 * 
	 */
	public void generateKeys() {
		try {
			
			final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
	        keyPairGenerator.initialize(1024);

	        final KeyPair keyPair = keyPairGenerator.generateKeyPair();

	        privateKey = keyPair.getPrivate();
	        publicKey  = keyPair.getPublic();
	    } 
		catch (Exception e) {
	       e.printStackTrace();
	    }
	}
	
	/**
	 * 
	 * @param mensajeRecibido2
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	public void receivePublicKeyFrom(String mensajeRecibido2) throws InvalidKeySpecException, NoSuchAlgorithmException {
		
		byte[] publicBytes = Base64.getDecoder().decode(mensajeRecibido2);
	    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
	    KeyFactory keyFactory = KeyFactory.getInstance("DH");
	    receivedPublicKey = keyFactory.generatePublic(keySpec);
    }
	/**
	 * 
	 */
	public void generateCommonSecretKey() {

        try {
            final KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(receivedPublicKey, true);

            secretKey = shortenSecretKey(keyAgreement.generateSecret());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

	private byte[] shortenSecretKey(final byte[] longKey) {

        try {
            final byte[] shortenedKey = new byte[8];

            System.arraycopy(longKey, 0, shortenedKey, 0, shortenedKey.length);

            return shortenedKey;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

}
