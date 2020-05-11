package cliente;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.KeyAgreement;

public class Cliente {

	//Datos conexi�n
	
	private int port=9000;
	private String ip="192.168.56.1";
	private Socket client;
    private DataOutputStream salida;
    private DataInputStream entrada;
    private String[] mensajeRecibido;
    private Scanner teclado;
    
    
    //Datos para el intercambio de claves  (diffie-hellman)
	
    private PrivateKey privateKey;
    private PublicKey  publicKey;
    private PublicKey  receivedPublicKey;
    private byte[]     secretKey;
    private String     secretMessage;
	
	
	public static void main(String[] args) {
		Cliente nuevoCliente = new Cliente();
		nuevoCliente.generateKeys();
		nuevoCliente.iniciarCliente();
	}

	private void iniciarCliente() {
		
		teclado = new Scanner(System.in);
        try{
        	client= new Socket(ip,port);
            salida = new DataOutputStream(client.getOutputStream());
            entrada = new DataInputStream(client.getInputStream());
            String msn = "";
            while(!msn.equals("x")){
                System.out.println("Escriba iniciar para comenzar la operacion");
                msn = teclado.nextLine();
                
                if(msn.equals("iniciar")) {
                	
                	//convertir publicKey del cliente a byte            
                	byte[] byte_pubkey = publicKey.getEncoded();

                	//convertir byte a String 
                	String publicKeyString = Base64.getEncoder().encodeToString(byte_pubkey);
           
                	//Enviamos la publickey convertida en string al servidor
                	salida.writeUTF("1-" + publicKeyString);
                }
             
                mensajeRecibido = entrada.readUTF().split("-");
            	
            	if(mensajeRecibido[0].equals("1")) {
            		//Recibimos la clave publica del cliente
            		receivePublicKeyFrom(mensajeRecibido[1]);
            		generateCommonSecretKey();
            		
            		// Hasta aqui lo que se ha hecho es generar una clave secreta en com�n
            		System.out.println("Clave secreta en com�n en el cliente: " + Base64.getEncoder().encodeToString(secretKey));
            	}
              
            }
            client.close();
        }catch(Exception e){
 
        }
	}
	
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
	
	public void receivePublicKeyFrom(String mensajeRecibido2) throws InvalidKeySpecException, NoSuchAlgorithmException {
		
		byte[] publicBytes = Base64.getDecoder().decode(mensajeRecibido2);
	    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
	    KeyFactory keyFactory = KeyFactory.getInstance("DH");
	    receivedPublicKey = keyFactory.generatePublic(keySpec);
    }

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
