package SinSeguridad;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.Security;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;


public class ServidorSS implements Runnable{
public static int TIME_OUT = 10000;
	
	public static int PUERTO = 80;
	
	public static int NTHREADS = 6; 
	
	private static ServerSocket socket;
	
	private static Semaphore sem;
	
	private static int id;
	
	public static void main(String[] args)
	{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		try 
		{
			socket = new ServerSocket(PUERTO);
			sem = new Semaphore(1);
			
			ServidorSS[] executors = new ServidorSS[NTHREADS];
			ExecutorService executor = Executors.newFixedThreadPool(NTHREADS);
			for( int i =0; i<NTHREADS; i++){
				executors[i] = new ServidorSS(i,sem);
				Runnable server = executors[i];
				executor.execute(server);
				System.out.println("executor " + i);
			}
		} catch (IOException e)
		{
			System.out.println("Hubo un error creando el server socket");
			e.printStackTrace();
		}
	}
	
	public ServidorSS(int nId, Semaphore semaphore) throws  SocketException {
		id = nId;
		sem = semaphore;
	}
	
	public void run() {
		while (true) {
			Socket s = null;

			try {
				sem.acquire();
				s = socket.accept();
				s.setSoTimeout(TIME_OUT);
			} catch (IOException e) {
				e.printStackTrace();
				sem.release();
				continue;
			} catch (InterruptedException e) {
				// Si hubo algun error tomando turno en el semaforo.
				// No deberia alcanzarse en condiciones normales de ejecucion.
				e.printStackTrace();
				continue;
			}
			sem.release();
			System.out.println("Thread " + id + " recibe a un cliente.");
			ProtocoloSS.atenderCliente(s);
			System.out.println("Atendiendo request con el hilo " + id);
		}
	}
	
	
}
