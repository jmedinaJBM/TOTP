
package com.jbm.pruebas.otp;

import com.google.common.io.BaseEncoding;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Funciones Time bases One Time Password para Autenticación de 2 factores.<br>
 * Contiene un conjunto de funciones utilizadas para la Autenticación de 2 Factores.
 * Permite generar un TOTP (Time bases One Time Password) basado en el estandar {@code RFC 6328}.
 * Este estandar nació de la Iniciativa para Autenticación Abierta (OATH en inglés).
 * <pre>
 *      Para que la utenticación de 2 factores funcione, se requiere de una aplicación que genere los códigos desde
 *      un dispositivo separado de la aplicación. Este pude ser Google Authenticator, capaz de generar códigos TOTP
 *      a partir de una <em>Clave Secreta</em>.
 * 
 *      Google Authenticator es propiedad de Google® y es gratuito; para generar los códigos TOTP no requiere conexión a internet.
 *      Esta Apps debe ser instalada en el SmartPhone del usuario que lo requiera.
 *      Google Authenticator está disponible para dispositivos {@code Android} y {@code iPhone}.
 * </pre>
 * @see <a href =https://www.wikiwand.com/en/Time-based_One-time_Password_algorithm>TOTP Wikipedia (english)</a> <br>
 * <a href =https://www.wikiwand.com/es/Google_Authenticator >Google Authenticator (español) </a> <br>
 * <a href =https://opensource.google.com/projects/guava>Guava: Google Core Libraries for Java API</a> <br>
 * <a href =https://tools.ietf.org/html/rfc6238#appendix-A>RFC 6328</a> <br>
 * 
 * @author Jairo Medina.
 *
 */
public final class TOTP {
                                                // 0 1 2 3 4 5 6 7 8 
    private static final int[] DIGITS_POWER = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 }; 
    
    private static final int        INTERVAL            = 60;
    /**
     * Ventana de tiempo para verficar el código TOTP. <br>Valor = 3. (aproximadamente 1 minuto 30 segundos de vida).
     */
    public static final int         WINDOW              = 4;
    /**
     * Longitud de los códigos TOTP generados. <br>Valor = 6.
     */
    public static final int         PASS_CODE_LENGTH    = 6;
    /**
     * Algoritmo Hash utilizado. <br>Valor = HmacSHA1
     */
    public static final String      CRYPTO              = "HmacSHA1"; 
    
    
    //---Constructores---
    //******************************************************************************************************************
    private TOTP() {}
    
    
    //---Métodos Públicos---
    //******************************************************************************************************************
    /**
     * <em>Tercer paso para usar TOTP.</em><br>
     * Obiene un código TOTP generado a partir de la {@code Clave Secreta} cifrada en Base32 dada por {@code secretKey}.
     * La longirud del {@code Código TOTP} generado está dado por {@link #PASS_CODE_LENGTH}.
     * @param secretKey Clave secreta codificada en Base32.
     * @return Código TOTP generado.
     */
    public static long      getCodeTOTP(String secretKey){
        byte[] decodedKey = TOTP.decodeSecretKey(secretKey);
        
        long currentInterval = getCurrentInterval();
        long hash = TOTP.generateTOTP(decodedKey, currentInterval, PASS_CODE_LENGTH, CRYPTO);
        return(hash);
    }
    
    /**
     * <em>Cuarto paso para usar TOTP.</em><br>
     * Determina si el código TOTP dado por {@code codeTOTP} es válido según los parámetros definidos por
     * {@link #WINDOW},  {@link #PASS_CODE_LENGTH} y {@link #CRYPTO}
     * @param secretKey Clave secreta codificada en Base32.
     * @param codeTOTP Código TOTP a verificar.
     * @return {@code True} El código es válido. {@code False} El código no es válido.
     */
    public static boolean   isValidCode(String secretKey, long codeTOTP) { 
        byte[] decodedKey = decodeSecretKey(secretKey);
        
        int window = WINDOW; 
        long currentInterval = getCurrentInterval(); 
        
        for (int i = -window; i <= window; ++i) { 
            long hash = TOTP.generateTOTP(decodedKey, currentInterval + i, PASS_CODE_LENGTH, CRYPTO); 
            if (hash == codeTOTP) { 
                return(true); 
            }
        }
        return(false);  // The code is invalid. 
    }
    
    
    /**
     * <em>Primer paso para usar TOTP.</em><br>
     * Genera un {@code Key} de 20 bytes de forma aleatoria, el cual es utilizado como {@code Clave Secreta}.
     * Con el Algoritmo {@code HmacSHA256} genera un hash y toma los primeros 20 byte de este.
     * @return Clave Secreta generada sin cifrar.
     * @throws NoSuchAlgorithmException Error al generar el Hash.
     * @see #getSecretKey(byte[]) 
     */
    public static byte[]    generateKey() throws NoSuchAlgorithmException{
        byte[] key = TOTP.getToken();
        key = Arrays.copyOf(key, 20);
        return(key);
    }
    
    /**
     * <em>Segundo paso para usar TOTP.</em><br>
     * Codifica en Base32, el {@code Key} pasado como argumento; {@code key} es una Clave de 20 byte sin cifrar.
     * Este {@code Key} debe ser generado con {@link #generateKey() }
     * La {@code Clave Secreta} generada, es la que se debe registrar en la App {@code Google Authenticator}.
     * Se utiliza la librería de <a href =https://opensource.google.com/projects/guava>Guava API</a> 
     * La clase utilizada es <em>com.google.common.io.BaseEncoding</em>
     * @param key Clave de 20 bytes sin cifrar.
     * @return Clave codificada en Base32. La logitud es de 32 byte (256-bits).
     */
    public static String    getSecretKey (byte[] key){
        BaseEncoding base32 = BaseEncoding.base32();
        String secretKey = base32.encode(key);
        return(secretKey);
    }
    
    /**
     * Genera una {@code Clave Secreta} cifrada en Base32.
     * <br>Resume las acciones de los métodos {@link #generateKey() } y {@link #getSecretKey(byte[]) } en un único método.
     * @return Clave cifrada en Base32.
     * @throws NoSuchAlgorithmException Error al generar el Hash.
     */
    public static String    getSecretKey() throws NoSuchAlgorithmException {
        byte[] bytes = TOTP.generateKey();
        String secretKey = getSecretKey(bytes);
        return(secretKey);
    }
    
    /**
     * Decodifica una {@code Clave Secreta} que ha sido cifrada en Base32.
     * Las {@code Claves Secetas} generadas por {@link #getSecretKey(byte[]) } y {@link #getSecretKey() } son decodificadas
     * por este método.
     * @param secretKey {@code Clave Secreta} cifrada en Base32.
     * @return Clave Secreta decodificada.
     */
    public static byte[]    decodeSecretKey(String secretKey){
        BaseEncoding base32 = BaseEncoding.base32();
        byte[] secretKeyDecode = base32.decode(secretKey);
        return(secretKeyDecode);
    }
    
    /**
     * Da formato a una {@code Clave Secreta} en un texto formado en grupos de cuatro separado por un espacio  para 
     * que sea más legible.
     * @param secretKey {@code Clave Secreta} cifrada en Base32.
     * @return Clave Secreta con formato.
     */
    public static String    getFormatedKey(String secretKey){
        return(secretKey.toUpperCase().replaceAll("(.{4})(?=.{4})", "$1 "));
    }
    
    
    //---Métodos Privados---
    //******************************************************************************************************************
    /**
  * This method generates a TOTP value for the given set of parameters. 
  *  
  * @param key  the shared secret
  * @param time a value that reflects a time
  * @param digits number of digits to return
  * @param crypto the crypto function to use 
  * @return digits 
  */ 
    private static int      generateTOTP(byte[] key, long time, int digits, String crypto) { 
        byte[] msg = ByteBuffer.allocate(8).putLong(time).array(); 
        byte[] hash = hmacSha(crypto, key, msg); 
        
        int offset = hash[hash.length - 1] & 0xf;   // put selected bytes into result int 
        
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff); 
        int otp = binary % DIGITS_POWER[digits];
        
        return(otp); 
    }
    
    /**
     * This method uses the JCE to provide the crypto algorithm. HMAC computes a 
     * Hashed Message Authentication Code with the crypto hash algorithm as a parameter. 
     * 
     * @param crypto the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512) 
     * @param keyBytes the bytes to use for the HMAC key 
     * @param text the message or text to be authenticated 
     */ 
    private static byte[]   hmacSha(String crypto, byte[] keyBytes, byte[] text) throws UndeclaredThrowableException { 
        try{
            Mac hmac; 
            hmac = Mac.getInstance(crypto); 
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW"); 
            hmac.init(macKey); 
            return hmac.doFinal(text); 
        } catch (GeneralSecurityException gse) { 
            throw new UndeclaredThrowableException(gse); 
        } 
    } 
    
    /**
     * Calcula el tiempo normalizado que será la base para el TOTP a generar.
     * @return Tiempo calculado y normalizado.
     */
    private static long     getCurrentInterval() { 
        long currentTimeSeconds = System.currentTimeMillis() / 1000; 
        return currentTimeSeconds / INTERVAL; 
    } 
    
    /**
     * Devuelve el {@code encode} de una clave generadoa de forma aleatoria.
     * <br>El tamaño del token es el definido por defecto en la constante.
     * @return Token generado.
     * @throws NoSuchAlgorithmException Error al generar el Token.
     */
    private static  byte[]       getToken         ()              throws NoSuchAlgorithmException{
        return(generateKey("HmacSHA256", 256).getEncoded());
    }
    
    /**
     * Genera una clave aleatoria.
     * @param algoritmo Algoritmo utilizado para generar la clave.
     * @param keySize Número de bits de la clave.
     * @return Clave generada.
     * @throws NoSuchAlgorithmException Error al generar la clave. Algortimo no válido.
     */
    private static  SecretKey    generateKey     (String algoritmo, int keySize)     throws NoSuchAlgorithmException{
        KeyGenerator kg = KeyGenerator.getInstance(algoritmo);
        SecureRandom sr = new SecureRandom();
        kg.init(keySize, sr);
        SecretKey key = kg.generateKey();
        return(key);
    }
}
