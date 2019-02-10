
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EmpaquetarExamen {
	
public static void main(String args[]) throws Exception{
		
        if (args.length != 4) {
			System.out.println("java -cp [...] EmpaquetarExamen <fichero examen> <nombre paquete> <ficheros con las claves necesarias> ");
			System.out.println(" Se necesitan 4 argumentos en este caso, ya que se necesitan dos ficheros con las claves: la clave privada del usuario y la clave publica");
			System.exit(1);
		}
	
    
    	// Anadir provider JCE (provider por defecto no soporta RSA)
		Security.addProvider(new BouncyCastleProvider());
		
		
		/*** Crear KeyFactory (depende del provider) usado para las transformaciones de claves*/
		KeyFactory keyRSA = KeyFactory.getInstance("RSA", "BC"); // Cifrado RSA, provider BC
		

		//Leer clave privada del fichero alumno.privada
		
		File ficheroClavePrivadaAlumno = new File(args[2]); 
		int tamanoFicheroClavePrivadaAlumno = (int) ficheroClavePrivadaAlumno.length();
		
		byte[] clavePrivadaA = new byte[tamanoFicheroClavePrivadaAlumno];
		FileInputStream in = new FileInputStream(ficheroClavePrivadaAlumno);
		in.read(clavePrivadaA, 0, tamanoFicheroClavePrivadaAlumno);
		in.close();
		
	
		//Recuperar la clave privada leida desde el fichero alumno.privada que estaba codificada en formato PKCS8
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(clavePrivadaA);
		
		PrivateKey clavePrivadaAlumno = keyRSA.generatePrivate(clavePrivadaSpec);
		
		
		
		// Leer clave publica del fichero profesor.publica
		File ficheroClavePublicaProfesor = new File(args[3]); 
		int tamanoFicheroClavePublicaProfesor = (int) ficheroClavePublicaProfesor.length();
		
		byte[] clavePublicaP = new byte[tamanoFicheroClavePublicaProfesor];
		in = new FileInputStream(ficheroClavePublicaProfesor);
		in.read(clavePublicaP, 0, tamanoFicheroClavePublicaProfesor);
		in.close();

		
		// 4.2 Recuperar clave publica desde datos codificados en formato X509
		X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(clavePublicaP);
		
		PublicKey clavePublicaProfesor = keyRSA.generatePublic(clavePublicaSpec);
		
                
        //Cargamos el fichero del examen        
        File examen = new File(args[0]);         
		
		//cifrar examen con DES a través de la funcion  cifrarDES de la clase cifradoDes que nos devuelve el examen cifrado
		cifradorDES cifrar = new cifradorDES();	
		byte[] examenCifrado = cifrar.cifrarDES(examen.toString().getBytes());
		
		byte[] claveDes = cifrar.mostrarClave();
		
		
		//cifrar la clave DES con la clave publica del profesor usando RSA
		CifradorRSA cifrarRsa= new CifradorRSA();
		byte [] examenCifradoConPublicaProfesor = cifrarRsa.cifrarClavePublica(claveDes, clavePublicaProfesor);
		
		//resumen de los datos del alumno (firma)
	
		/* Cargar "provider" (sólo si no se usa el que viene por defecto) */
		// Security.addProvider(new BouncyCastleProvider());  // Usa provider BC
		
		/* Crear función resumen */
		MessageDigest messageDigest = MessageDigest.getInstance("MD5"); // Usa MD5

		messageDigest.update(examen.toString().getBytes());			
		byte[] resumenHash = messageDigest.digest(); // Completar el resumen

		
		//cifrar el resumen del alumno con RSA
		CifradorRSA cifrarRsaResumen= new CifradorRSA();
		byte[] resumenCifradoConPrivadaAlumno = cifrarRsaResumen.cifrarClavePrivada(resumenHash, clavePrivadaAlumno);
		
		//solo es prueba para ver si descifra bien
		//cifrarRsaReseumenPere.descifrarClavePublica(resumenCifradoPublico);
		
		
		//se empaqueta los datos cifrados del alumnos creando bloques
		Bloque b1 = new Bloque("Datos del examen del alumno",examenCifrado);//examen
		Bloque b2 = new Bloque("Resumen del examen del alumno", resumenCifradoConPrivadaAlumno); //firma
		Bloque b3 = new Bloque("Clave cifrada con RSA",examenCifradoConPublicaProfesor);//clave 
		
		//paquete donde metemos los datos
		Paquete p1 = new Paquete();
		p1.anadirBloque("Datos del examen del alumno", b1);
		p1.anadirBloque("Clave cifrada con RSA", b3);
		p1.anadirBloque("Resumen del examen del alumno", b2);
		
		
		//creamos una variable paqueteDAO para guardar p2 en un fichero
		PaqueteDAO p2 = new PaqueteDAO();
		p2.escribirPaquete(args[1], p1);
		
	}
}
