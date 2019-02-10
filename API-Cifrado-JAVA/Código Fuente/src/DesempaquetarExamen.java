import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DesempaquetarExamen  {
	
	public static void main(String[] args) throws Exception {
		
		
		if (args.length != 5) {
			System.out.println("java -cp [...] DesempaquetarExamen <nombre paquete> <fichero examen> <ficheros con las claves necesarias>");
			System.out.println(" Se necesitan 5 argumentos en este caso, ya que se necesitan dos ficheros con las claves: la clave privada del profesor y las dos claves publicas de alumno y autoridad");
			System.exit(1);
		}

		
		
		Security.addProvider(new BouncyCastleProvider());
		
		
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC"); // Hace uso del provider BC
		

		// recuperar clave privada del profesor del fichero profesor.privada
		
		File ficheroClaveProfesor = new File(args[2]); 
		int tamanoFicheroClaveProfesor = (int) ficheroClaveProfesor.length();
		byte[] clavePrivadaP = new byte[tamanoFicheroClaveProfesor];
		FileInputStream in = new FileInputStream(ficheroClaveProfesor);
		in.read(clavePrivadaP, 0, tamanoFicheroClaveProfesor);
		in.close();
		
		//recuperar clave privada desde datos codificados en formato PKCS8
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(clavePrivadaP);
		
		PrivateKey clavePrivadaProfesor = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

		// recuperar la clave publica del alumno del fichero alumno.publica

		File ficheroClavePublicaAlumno = new File(args[3]); 
		int tamanoFicheroClavePublicaAlumno = (int) ficheroClavePublicaAlumno.length();
		byte[] clavePrivadaA = new byte[tamanoFicheroClavePublicaAlumno];
		in = new FileInputStream(ficheroClavePublicaAlumno);
		in.read(clavePrivadaA, 0, tamanoFicheroClavePublicaAlumno);
		in.close();
		
		// Recuperar clave publica desde datos codificados en formato X509
		X509EncodedKeySpec clavePublicaSpecA = new X509EncodedKeySpec(clavePrivadaA);
		
		PublicKey clavePublicaAlumno = keyFactoryRSA.generatePublic(clavePublicaSpecA);

		// recuperar la clave publica de la autoridad de sellado del fichero autoridadSellado.publica

		File ficheroClavePublicaAutoridadSellado = new File(args[4]); 
		int tamanoFicheroClavePublicaAutoridadSellado = (int) ficheroClavePublicaAutoridadSellado.length();
		byte[] clavePublicaAS = new byte[tamanoFicheroClavePublicaAutoridadSellado];
		in = new FileInputStream(ficheroClavePublicaAutoridadSellado);
		in.read(clavePublicaAS, 0, tamanoFicheroClavePublicaAutoridadSellado);
		in.close();
		
		// Recuperar clave publica desde datos codificados en formato X509
		X509EncodedKeySpec clavePublicaSpecAS = new X509EncodedKeySpec(clavePublicaAS);
		
		PublicKey clavePublicaAutoridadSellado = keyFactoryRSA.generatePublic(clavePublicaSpecAS);
		
		
		// buscar dentro del paquete la clave secreta
		PaqueteDAO paq = new PaqueteDAO();
		Bloque bloq = new Bloque();

		// Leer el examen cifrado con DES y cifrado con la clave publica del profesor
		bloq = paq.leerPaquete(args[0]).getBloque("Clave cifrada con RSA");
		
		

		// Leer el resumen del alumno (firma) cifrado con su clave privada y lo desciframos con RSA
		Bloque bloqueResumenAlumno = new Bloque();

		Paquete paqueteArchivoLeido = paq.leerPaquete(args[0]);

		bloqueResumenAlumno = paqueteArchivoLeido.getBloque("Resumen del examen del alumno");

		CifradorRSA descifrarResumenAlumno = new CifradorRSA();
		
		byte[] resumenAlumno = descifrarResumenAlumno.descifrarClavePublica(bloqueResumenAlumno.getContenido(),
				clavePublicaAlumno);

		// descifrar usando RSA con la clave privada del profesor, el examen cifrado con DES 
		//( cifrado con la clave publica del profesor) 
		
		CifradorRSA descifrarClave = new CifradorRSA();
		byte[] bufferClaveDes = descifrarClave.descifrarClavePrivada(bloq.getContenido(), clavePrivadaProfesor);
		SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
		DESKeySpec DESspec = new DESKeySpec(bufferClaveDes);
		SecretKey claveSecreta = secretKeyFactoryDES.generateSecret(DESspec);

		
		Bloque bloqueDes = new Bloque();
		bloqueDes = paq.leerPaquete(args[0]).getBloque("Datos del examen del alumno");

		
		//Descifrar con DES el examen del alumno
		cifradorDES desCifrarDes = new cifradorDES();
		byte[] datosDescifradosAlumno = desCifrarDes.descifrarDES(bloqueDes.getContenido(), claveSecreta);

		// hacer el resumen de los datos recien descifrados para compararlos con la firma del alumno.

		/* Cargar "provider" (sólo si no se usa el que viene por defecto) */
		// Security.addProvider(new BouncyCastleProvider());  // Usa provider BC
		
		/* Crear función resumen */
		MessageDigest messageDigest = MessageDigest.getInstance("MD5"); // Usa MD5

		
		messageDigest.update(datosDescifradosAlumno);			
		byte[] resumenHashComprobacion = messageDigest.digest(); // Completar el resumen
		
	

		// Comparar el resumen del alumno hecha con su clave privada (firma)
		//con el resumen que acabamos de hacer para saber si los datos son correctos
		boolean alumno = false;
		if (Arrays.equals(resumenHashComprobacion, resumenAlumno)) {
			System.out.println("Correcto.");
			alumno = true;
		} else
			System.out.println("Incorecto.");

		// firma de la autoridad de sellado hecha con su clave privada
		Bloque resumenAutoridadSellado = new Bloque();
		resumenAutoridadSellado = paqueteArchivoLeido.getBloque("Resumen del alumno-autoridad de sellado");
		// descifrar el resumen con la clave publica de la autoridad de sellado
		byte[] resumenDescifradoAutoridadSellado = descifrarClave.descifrarClavePublica(resumenAutoridadSellado.getContenido(),
				clavePublicaAutoridadSellado);

		// hacer de nuevo el resumen hash de la autoridad de sellado concatenado con la firma del alumno para comprobar si 
		// son iguales a los resumenes descifrados

		
		
		// Leer la fecha mas la firma del alumno (resumen del examen)
		Bloque fechaAutoridadSellado = new Bloque();
		fechaAutoridadSellado = paqueteArchivoLeido.getBloque("Datos de la autoridad de sellado");
		
		// concatenar la fecha de la  autoridad de sellado y el resumen del alumno
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(fechaAutoridadSellado.getContenido());
		outputStream.write(bloqueResumenAlumno.getContenido());
		
		// bloque concatenado
		byte c[] = outputStream.toByteArray();
		
		// resumir con hash

		/* Cargar "provider" (sólo si no se usa el que viene por defecto) */
		// Security.addProvider(new BouncyCastleProvider());  // Usa provider BC
		
		/* Crear función resumen */
		MessageDigest messageDigest2 = MessageDigest.getInstance("MD5"); // Usa MD5

		
		messageDigest2.update(c);			
		byte[] resumenHashComprobacionAutoridadSellado = messageDigest2.digest(); // Completar el resumen
		
		
		//Comprobamos que el resumen de la autoridad de sellado y el del alumno son iguales
		boolean autoridadSellado = false;
		
		if (Arrays.equals(resumenHashComprobacionAutoridadSellado, resumenDescifradoAutoridadSellado)) {
			System.out.println("Autoridad de sellado Correcto");
			autoridadSellado = true;
			} else{
				System.out.println("Autoridad de sellado Incorrecto ");
				}
		

		if (alumno && autoridadSellado){
			System.out.println("Examen valido");
			}else{
				System.out.println("Error.");
				}

	}
	
	
	
	
	
	

}
