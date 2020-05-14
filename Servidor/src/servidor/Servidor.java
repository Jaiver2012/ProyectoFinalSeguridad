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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

public class Servidor {

	//Data for connection
	private ServerSocket server;
	private Socket socket;
	private int port=9000;
	private DataInputStream dataInputOne;
	private DataOutputStream dataOutputOne;
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

	private SecretKeySpec claveAES;

    
	/**
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		
		Servidor newServer = new Servidor();
		newServer.generateKeys();
		newServer.initServer();
	}
	
	/**
	 * 
	 */
	private  void initServer() {
		
		try {
			System.out.println("Iniciando servidor en el puerto: "+port);
			server= new ServerSocket(port);
			socket= new Socket();
			System.out.println("-------------------------------------------------------------------------------------------------------");
			System.out.println("Esperando la conexión con el cliente por el puerto "+ port+ ":localhost...");
			
            while(true){
            	
            	socket=server.accept();
            	System.out.println("Conectado a " + socket.getRemoteSocketAddress()); 
            	
            	dataInputOne= new DataInputStream(socket.getInputStream());
            	dataOutputOne= new DataOutputStream(socket.getOutputStream());
                
            	mensajeRecibido = dataInputOne.readUTF().split("-");
            	//System.out.println("esto llego:"+mensajeRecibido[2]);
            	if(mensajeRecibido[0].equals("1")) {
            		//Recibimos la clave publica del cliente
            		receivePublicKeyFrom(mensajeRecibido[1]);
            		generateCommonSecretKey();
            		System.out.println("Clave secreta en común en el servidor: " + Base64.getEncoder().encodeToString(secretKey));
                	//Nombre del archivo a transferir
            		//System.out.println("Nombre del archivo a tranferir: " + entrada.readUTF());
            		//convertir publicKey del servidor a byte            
                	byte[] byte_pubkey = publicKey.getEncoded();

                	//convertir byte a String 
                	String publicKeyString = Base64.getEncoder().encodeToString(byte_pubkey);
           
                	//Mandar la publickey convertidad en string al cliente
                	dataOutputOne.writeUTF("1-" + publicKeyString);
            		
                	// Hasta aqui lo que se ha hecho es generar una clave secreta en común
            		
                	
                	
                	//-----------------------------------------------------------------------------------------------------------------------------
                	// Recieve file of client
                	//-----------------------------------------------------------------------------------------------------------------------------
                	recieveFile();
                	
            	}
            	
            	System.out.println("-------------------------------------------------------------------------------------------------------");
    			System.out.println("Esperando la conexión con el cliente por el puerto "+ port+ ":localhost...");
            }
			//socket.close();
		} 
		catch (Exception e) {
			// TODO: handle exception
		}
	}
	
	/**
	 * 
	 * @param pathfile
	 */
	public void recieveFile(){
		
		try {
			System.out.println("Recibiendo archivo del cliente");
        	receivedData = new byte[1024];
        	bis = new BufferedInputStream(socket.getInputStream());
        	DataInputStream dis=new DataInputStream(socket.getInputStream());
        	//Recibimos el nombre del fichero
        	file = desencriptar(dis.readUTF());
        	file = file.substring(file.indexOf('\\')+1,file.length());
        	//Para guardar fichero recibido
        	bos = new BufferedOutputStream(new FileOutputStream(file));
        	while ((in = bis.read(receivedData)) != -1){
        		bos.write(receivedData,0,in);
        	}
        	System.out.println("Archivo guardado exitosamente");
        	bos.close();
        	dis.close();

		}catch(Exception e) {
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
	
	public String desencriptar(String datosEncriptados) throws Exception {
        crearClave();
 
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, claveAES);
         
        byte[] bytesEncriptados = Base64.getDecoder().decode(datosEncriptados);
        byte[] datosDesencriptados = cipher.doFinal(bytesEncriptados);
        String datos = new String(datosDesencriptados);
         
        return datos;
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
