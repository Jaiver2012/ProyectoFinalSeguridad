package servidor;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;

public class Connection {

	

	ServerSocket server;
	Socket socket;
	int puerto=9000;
	DataOutputStream salida;
	BufferedReader entrada;
	boolean flag=true;
	
	public void iniciar() {
		
		
		
		try {
			server= new ServerSocket(puerto);
			socket= new Socket();
			while(flag) {
				socket=server.accept();

				entrada= new BufferedReader(new InputStreamReader(socket.getInputStream()));
				String mensaje = entrada.readLine();
				System.out.println(mensaje);
				
				
				salida= new DataOutputStream(socket.getOutputStream());
				salida.writeUTF("Bye mundo cruel");
				socket.close();
			}
			
			
			
			
		}catch (Exception e) {
			// TODO: handle exception
		}
	}
	
	
}
