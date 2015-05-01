package ConSeguridad;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;


public class ProtocoloCS {
	
	public final static String SEP = ":";

	
	
	public static void cerrarConexiones( InputStreamReader input, BufferedReader buff, PrintWriter printer, OutputStream output, Socket socket) throws IOException {
		buff.close();
		printer.close();
		output.close();
		input.close();
		socket.close();	
	}

	public static void atenderCliente(Socket socket)
	{
		try
		{
			InputStreamReader input = new InputStreamReader(socket.getInputStream());
			OutputStream output = socket.getOutputStream();
			BufferedReader buff = new BufferedReader(input);
			PrintWriter printer = new PrintWriter(output, true);
			
			String linea = buff.readLine();
			if( linea.equals("HOLA")){
				
				System.out.println("Llego a HOLA");
				printer.println("INICIO");;
				printer.flush();
				
				String linea1 = buff.readLine();
				if(!linea1.equals("") && linea1.contains(SEP) && linea1.startsWith("ALGORITMOS")){
					String[] algoritmos = linea1.split(SEP);
					String simetrico = algoritmos[1];
					String asimetrico = algoritmos[2];
					String hash = algoritmos[3];
					
					if( simetrico.equals("DES") || simetrico.equals("AES") || simetrico.equals("BLOWFISH") || simetrico.equals("RC4")){
						if(asimetrico.equals("RSA")){
							if(hash.equals("HMACMD5") || hash.equals("HMACSHA1") || hash.equals("HMACSHA256")){
								
								System.out.println("Llego a ALGORITMOS");
								
								printer.println("ESTADO:OK");
								printer.flush();
								
								String linea2 = buff.readLine();
								if(linea2.equals("CERCLNT")){
									
									System.out.println("Llego a CERCLNT");	
									
									AlgoritmosCertificados seguridad = new AlgoritmosCertificados(); 
									
									byte[] certificadoServidorBytes = new byte[520];
									socket.getInputStream().read(certificadoServidorBytes);
									
									X509Certificate certificadoCliente = seguridad.crearCertificado(certificadoServidorBytes);
									
									printer.println("CERTSRV");
									KeyPair llavesAsimetricas = seguridad.generarLlavesAsimetricas();
									X509Certificate certSer = seguridad.generarCertificado(llavesAsimetricas);
									
									socket.getOutputStream().write(certSer.getEncoded());
									socket.getOutputStream().flush();
									System.out.println("Llego a CERTSRV");
									
									SecretKey llaveSimetrica =seguridad.generarLlaveSimetrica(simetrico);
									byte[] llaveCifrada = seguridad.cifradoAsimetrico(llaveSimetrica.getEncoded(), certificadoCliente.getPublicKey(), asimetrico);
									printer.println("INIT:" + seguridad.hexaString(llaveCifrada));
									
									System.out.println("Llego a INIT");
									
									String linea5 = buff.readLine();
									if( linea5.startsWith("ACT1")){
										
										String[] coo = linea5.split(SEP);
										byte[] bs = seguridad.stringHexa(coo[1]);
										String coordenadas = new String(seguridad.descifradoSimetrico(bs, llaveSimetrica, simetrico));
										
										String linea6 = buff.readLine();
										if( linea6.startsWith("ACT2")){
											String[] coo2 = linea6.split(SEP);
											byte[] bs2 = seguridad.stringHexa(coo2[1]);
											
											byte[] hmac = seguridad.descifradoAsimetrico(bs2, llavesAsimetricas.getPrivate(), asimetrico);
											
											boolean respuesta = seguridad.verificarIntegridad(coordenadas.getBytes(), llaveSimetrica, hash, hmac);
											if(respuesta){
												printer.println("RTA:OK");
												
											}
											else{
												printer.println("RTA:ERROR");
											}
											cerrarConexiones(input, buff, printer, output, socket);
										}
										else{
											System.out.println("No llego el mensaje esperado, este fue el mensaje: " + linea6);
											cerrarConexiones(input, buff, printer, output, socket);
										}
									}
									else{
										System.out.println("No llego el mensaje esperado, este fue el mensaje: " + linea5);
										cerrarConexiones(input, buff, printer, output, socket);
									}
									
								}
								else{
									System.out.println("No llego el mensaje esperado, este fue el mensaje: " + linea2);
									cerrarConexiones(input, buff, printer, output, socket);
								}
							}
							else{
								System.out.println("Este algoritmo hash no es soportado: " + hash);
								printer.println("ESTADO:ERROR");
								printer.flush();
								cerrarConexiones(input, buff, printer, output, socket);
							}
						}
						else{
							System.out.println("Este algoritmo asimetrico no es soportado: " + asimetrico);
							printer.println("ESTADO:ERROR");
							printer.flush();
							cerrarConexiones(input, buff, printer, output, socket);
						}
					}
					else{
						System.out.println("Este algoritmo simetrico no es soportado: " + simetrico);
						printer.println("ESTADO:ERROR");
						printer.flush();
						cerrarConexiones(input, buff, printer, output, socket);
					}
				}
				else{
					System.out.println("No está escrito en el protocolo que debería, este fue el mensaje: " + linea1);
					cerrarConexiones(input, buff, printer, output, socket);
				}
			}
			else{
				System.out.println("No llegó HOLA, el mensaje que llego fue: " + linea);
				cerrarConexiones(input, buff, printer, output, socket);
			}
			
		} catch (IOException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (IllegalStateException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
