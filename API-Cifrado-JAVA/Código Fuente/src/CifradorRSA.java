import java.security.*;
import   javax.crypto.*;


// Necesario para usar el provider Bouncy Castle (BC)
//    Para compilar incluir el fichero JAR en el classpath
// 
public class CifradorRSA  {	
	
	private Cipher cifrador;
	
	
	public CifradorRSA () throws Exception {
		
		 //Crear e inicializar el par de claves RSA DE 512 bits
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC"); // Hace uso del provider BC
        keyGen.initialize(512);  // tamano clave 512 bits
              
        this.cifrador = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC
		
        /************************************************************************
         * IMPORTANTE: En BouncyCastle el algoritmo RSA no funciona realmente en modo ECB
         *		  * No divide el mensaje de entrada en bloques
         *                  * Solo cifra los primeros 512 bits (tam. clave)
         *		  * Para cifrar mensajes mayores, habría que hacer la 
         *                    división en bloques "a mano"
         ************************************************************************/
		
	}
	
   
   //Cifrar con clave publica
   public  byte[] cifrarClavePublica(byte[] textoACifrar, PublicKey clavePublica) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException{
	   
	   	  //Poner cifrador en modo CIFRADO 
	   	  this.cifrador.init(Cipher.ENCRYPT_MODE, clavePublica);  // Cifra con la clave publica
	      
	      byte[] bufferCifrado  = this.cifrador.doFinal(textoACifrar);	      
	      
	      return bufferCifrado;
	      
   }
   
   //Descifrar con clave publica
   public  byte[] descifrarClavePublica(byte[] textoADescifrar, PublicKey clavePublica) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException{
	   
	   	  //Poner cifrador en modo DESCIFRADO 
	      this.cifrador.init(Cipher.DECRYPT_MODE, clavePublica); // Descrifra con la clave privada
  
	      byte[] bufferDescifrado = this.cifrador.doFinal(textoADescifrar);	      
	      
	      return bufferDescifrado;
   }
   
   
   //Cifrar con clave privada
   public  byte[] cifrarClavePrivada(byte[] textoACifrar, PrivateKey clavePrivada) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException{
	      
		   //Poner cifrador en modo CIFRADO 
		   this.cifrador.init(Cipher.ENCRYPT_MODE, clavePrivada);  // Cifra con la clave privada
		      
		   byte[] bufferCifrado  = this.cifrador.doFinal(textoACifrar);
		   		   
		   return bufferCifrado;
   }
   
  //descifrar clave privada 
   public byte[] descifrarClavePrivada(byte[] textoaDescifrar, PrivateKey clavePrivada) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException{
	   
	   
	   //Poner cifrador en modo DESCIFRADO 
	   this.cifrador.init(Cipher.DECRYPT_MODE, clavePrivada); // Descrifra con la clave privada
	   
	   byte[] bufferDescifrado = this.cifrador.doFinal(textoaDescifrar);
	   	   
	   return bufferDescifrado;
   }


	
}

