import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class cifradorDES {
	/*  Ejemplo de uso de funciones de resumen Hash
	 *   carga el fichero que recibe como parametro, lo cifra y lo descifra
	 */
	public SecretKey clave;
	
	public byte[] cifrarDES(byte[] c) throws Exception {
		
		/* Cargar "provider" (sólo si no se usa el que viene por defecto) */
		// Security.addProvider(new BouncyCastleProvider());  // Usa provider BC 
		
		/* PASO 1: Crear e inicializar clave */
		byte[] toret;
		
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56); // clave de 56 bits
		clave = generadorDES.generateKey();
		

		/* PASO 2: Crear cifrador */
		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
		// Algoritmo DES
		// Modo : ECB (Electronic Code Book)
		// Relleno : PKCS5Padding	
				
		
		/* PASO 3a: Inicializar cifrador en modo CIFRADO */
		cifrador.init(Cipher.ENCRYPT_MODE, clave);
				
		toret=cifrador.doFinal(c); // Completar cifrado (procesa relleno, puede devolver texto)

		
		return toret;
	}
	
	
	public byte[] descifrarDES(byte[] textoCifrado, SecretKey clave) throws Exception {
		
		/* Cargar "provider" (sólo si no se usa el que viene por defecto) */
		// Security.addProvider(new BouncyCastleProvider());  // Usa provider BC
		// 

		/* PASO 2: Crear cifrador */
		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");	

		
		/* PASO 3b: Poner cifrador en modo DESCIFRADO */
		byte[] descifrado = null;
		
		cifrador.init(Cipher.DECRYPT_MODE, clave);	
		descifrado=(cifrador.doFinal(textoCifrado));// Completar descifrado (procesa relleno, puede devolver texto)
		
		
		return descifrado;
	}
	
	
	public  byte[] mostrarClave() {
		
		return clave.getEncoded();
		} 
		
		public  void mostrarBytesDES(String s) {
			
			System.out.println("DES "+s);
			}
		
	
	

	
	
	
}