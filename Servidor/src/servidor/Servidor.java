package servidor;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
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

import javax.crypto.KeyAgreement;

public class Servidor {

	//Datos de conexion
	private ServerSocket server;
	private Socket socket;
	private int puerto=9000;
	private DataOutputStream salida;
	private DataInputStream entrada;
	private String[] mensajeRecibido;
	
	BufferedInputStream bis;
	 BufferedOutputStream bos;
	 
	byte[] receivedData;
	 int in;
	 String file;
	
	
	//Datos para el intercambio de claves  (diffie-hellman)
	

    private PrivateKey privateKey;
    private PublicKey  publicKey;
    private PublicKey  receivedPublicKey;
    private byte[]     secretKey;
    private String     secretMessage;
    
    
    
	
	public static void main(String[] args) {
		
		Servidor nuevoServidor = new Servidor();
		nuevoServidor.generateKeys();
		nuevoServidor.iniciarServidor();
	}

	private  void iniciarServidor() {
		try {
			server= new ServerSocket(puerto);
			socket= new Socket();
			socket=server.accept();
			entrada= new DataInputStream(socket.getInputStream());
			salida= new DataOutputStream(socket.getOutputStream());
			String msn = "";
            while(!msn.equals("x")){
                
            	mensajeRecibido = entrada.readUTF().split("-");
            	//System.out.println("esto llego:"+mensajeRecibido[2]);
            	if(mensajeRecibido[0].equals("1")) {
            		//Recibimos la clave publica del cliente
            		receivePublicKeyFrom(mensajeRecibido[1]);
            		generateCommonSecretKey();
            		System.out.println("Clave secreta en com�n en el servidor: " + Base64.getEncoder().encodeToString(secretKey));
                	//Nombre del archivo a transferir
            		//System.out.println("Nombre del archivo a tranferir: " + entrada.readUTF());
            		//convertir publicKey del servidor a byte            
                	byte[] byte_pubkey = publicKey.getEncoded();

                	//convertir byte a String 
                	String publicKeyString = Base64.getEncoder().encodeToString(byte_pubkey);
           
                	//Mandar la publickey convertidad en string al cliente
                	salida.writeUTF("1-" + publicKeyString);
            		
                	// Hasta aqui lo que se ha hecho es generar una clave secreta en com�n
            		
                	//se llama el enviar archvo
                	sendFile(mensajeRecibido[2]);
                	
            	}
 
            }
			socket.close();
		} 
		catch (Exception e) {
			// TODO: handle exception
		}
	}
	
	public void sendFile(String pathfile){
		
		try {
			receivedData = new byte[1024];
			 bis = new BufferedInputStream(socket.getInputStream());
			// DataInputStream dis=new DataInputStream(socket.getInputStream());
			 
			 //Recibimos el nombre del fichero
			 file = pathfile;
			 file = file.substring(file.indexOf('\\')+1,file.length());
			 //Para guardar fichero recibido
			 bos = new BufferedOutputStream(new FileOutputStream(file));
			 while ((in = bis.read(receivedData)) != -1){
				 bos.write(receivedData,0,in);
				 }
				 bos.close();
				
		}catch(Exception e) {
			
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
