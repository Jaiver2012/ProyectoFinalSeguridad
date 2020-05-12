package cliente;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Socket;

public class ConnectionClient {

Socket client;
int port=9000;
String ip="192.168.56.1";
BufferedReader entrada, teclado;
PrintStream salida;

public void iniciar() {
	
	try {
		client= new Socket(ip,port);
		entrada= new BufferedReader(new InputStreamReader(client.getInputStream()));
		teclado= new BufferedReader(new InputStreamReader(System.in));
		String tec=teclado.readLine();
		salida= new PrintStream(client.getOutputStream());
		salida.println(tec);
		String msg=entrada.readLine();
		System.out.println(msg);
		
		entrada.close();
		salida.close();
		teclado.close();
		client.close();
	}catch (Exception e) {
		// TODO: handle exception
	}
}

	
	
}
