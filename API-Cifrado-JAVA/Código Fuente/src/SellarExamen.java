import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SellarExamen {

	public static void main(String[] args) throws Exception {
		
        if (args.length != 2) {
			System.out.println("java -cp [...] SellarExamen <nombre paquete> <ficheros con las claves necesarias> ");
			System.out.println(" Se necesitan 2 argumentos en este caso, ya que se necesitan un fichero con la clave privada de la autoridad de sellado");
			System.exit(1);
		}
		
		Security.addProvider(new BouncyCastleProvider());

		
		//Leer clave privada del fichero autoridadSellado.privada
		File ficheroClavePrivadaAutoridadSellado =  new File(args[1]); 
		int tamanoFicheroClavePrivadaAutoridadSellado = (int) ficheroClavePrivadaAutoridadSellado.length();
		
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC"); // Hace uso del provider BC
		byte[] clavePrivadaAS = new byte[tamanoFicheroClavePrivadaAutoridadSellado];
		FileInputStream in = new FileInputStream(ficheroClavePrivadaAutoridadSellado);
		in.read(clavePrivadaAS, 0, tamanoFicheroClavePrivadaAutoridadSellado);
		in.close();
		
		//recuperar clave privada desde datos codificados en formato PKCS8
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(clavePrivadaAS);
		PrivateKey clavePrivadaAutoridadSellado = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
		
		

		//lectura del paquete con la informacion

		PaqueteDAO paq = new PaqueteDAO();
		Bloque bloq = new Bloque();
		
		//recoger el resumen cifrado del alumno(firma)
		bloq =  paq.leerPaquete(args[0]).getBloque("Resumen del examen del alumno");
	
		
		LocalDate ahora = LocalDate.now();
		
		byte[] FechaAutoridadSellado = ahora.toString().getBytes();
		byte[] infoFirmaAlumno = bloq.getContenido();
		
		
		//concatenar los byte[] de alumno y autoridad sellado(fecha)
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write( FechaAutoridadSellado );
		outputStream.write( infoFirmaAlumno );
		
		//bloque concatenado
		byte PaqueteFecha[] = outputStream.toByteArray();
		
		/* Cargar "provider" (sólo si no se usa el que viene por defecto) */
		// Security.addProvider(new BouncyCastleProvider());  // Usa provider BC
		
		/* Crear función resumen */
		MessageDigest messageDigest = MessageDigest.getInstance("MD5"); // Usa MD5
	
		messageDigest.update(PaqueteFecha);			
		byte[] resumenHash = messageDigest.digest(); // Completar el resumen
			
		//cifrar con rsa el resumen
		CifradorRSA cifrarRsaResumenAutoridadSellado= new CifradorRSA();
		byte[] firmaAutoridadSellado = cifrarRsaResumenAutoridadSellado.cifrarClavePrivada(resumenHash, clavePrivadaAutoridadSellado);
		
		
		//crear el paquete de la autoridad de sellado
		//empaquetar los datos cifrados del alumno
		Bloque b1 = new Bloque("Datos de la autoridad de sellado",FechaAutoridadSellado);
		Bloque b2 = new Bloque("Resumen del alumno-autoridad de sellado", firmaAutoridadSellado);
		
		PaqueteDAO paqueteAlumno = new PaqueteDAO();
		Paquete paqueteAlumnoInicial = new Paquete();
		paqueteAlumnoInicial=paqueteAlumno.leerPaquete(args[0]);
		
		
		//meter los datos de la autoridad de sellado en el paquete del alumno
		
		paqueteAlumnoInicial.anadirBloque("Datos de la autoridad de sellado", b1);
		paqueteAlumnoInicial.anadirBloque("Resumen del alumno-autoridad de sellado", b2);
		
		//escribir en el fichero
		paq.escribirPaquete(args[0], paqueteAlumnoInicial);
		
	}

}
