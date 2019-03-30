# Autenticación de 2 Factores Java
La Autenticación de 2 Factores (**2FA** por sus siglas en inglés), es un mecanismo para asegurar la identidad del usuario con el fin de proteger sus recursos. Los grandes de la Industria de TI como las Redes Sociales y Bancos utilizan este mecanismo, muy efectivo y sencillo de implementar en todo tipo de aplicaciones. Está basado en la Tecnología **TOTP**, *Time-based One Time Password*, por sus siglas en inglés, es un estandar definido en el [RFC 6328][rfc6328].
<br/><br/>
Cuando accedemos a nuestros recursos, lo hacemos tradicionalmente con un usuario y contraseña, que se supone solo nosotros conocemos. Pero qué pasa si alguien averigua nuestro usuario y contraseña? La solución es añadir un elemento más de seguridad. Algunos lo conocen como Token, pero técnicamente se le conoce como Clave de Una Vez Basada en el Tiempo, TOTP por sus siglas en inglés; este es un Código que solamente lo podrás utilizar una vez, que tiene un tiempo de caducidad porque que es generado en función del tiempo.

## TOTP
Es el estandar que sirve para implementar 2FA. Consiste en utilizar el SmartPhone con una aplicación que genera las Claves que deberás proporcionar a la aplicación que quieres acceder, posterior a que hayas ingresado tu Usuario y Contraseña. Google Authenticator es una App de Google que genera Claves TOTP, es gratuita y está disponible para Android y iOS.<br/><br/>

Para incorporar en una aplicación Java, este segundo Factor (**2FA**), sea de escritorio o web, es necesario hacer lo siguiente:
- [x] Implementar lo que dice el [RFC 6328][rfc6328]. En el ejmplo he creado una clase llamada TOTP con los métodos correspondientes. 
- [x] Instalar [Google Authenticator][googleauthtenticator] en un SmartPhone (Android o iOS).
- [x] Generar una Clave Secreta e instalarla en Google Authenticator. En el ejemplo hay métodos desarrollados.
- [x] Verificar el código TOTP generado por Google Authenticator.

## Ejemplo con Java

### Requsitos del Proyecto Java
1. [NetBeans 8.2](https://netbeans.org/downloads/)
2. [Java SE JDK 1.8](https://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html?fbclid=IwAR21GQMtgfZY7ZzLscX538bwGPkzqT8ap2jXCFUy0Ycnmxqy4hEDja7XPJo) update más reciente.
3. [Apache Maven 3.6](https://www-us.apache.org/dist/maven/maven-3/3.6.0/binaries/apache-maven-3.6.0-bin.zip?fbclid=IwAR2pO8S7v5Frm0eKYDoTemFWSu7w0fIYOIXsDrmrthNlUKGHQbF6uN5TkoM)
4. [Google Guava 14.0.1](https://repo1.maven.org/maven2/com/google/guava/guava/14.0.1/) Es parte del *Core Libraries for Java API* de Google.
```java
<dependency>
    <groupId>com.google.guava</groupId>
    <artifactId>guava</artifactId>
    <version>14.0.1</version>
    <type>jar</type>
</dependency>
```
### Implementación
**Paso 1.** Generar la **Clave Secreta** para [Google Authenticator][googleauthtenticator]. <br/>Esta *clave secreta* es un hash de 20 byte (160 bits) que se debe cifrar en **Base32**. La clave resultante de 32 byte (256 bits), es la que debes registrar para un usuario específico; se debe generar una clave secreta para cada usuario. Para este cifrado utilizo la librería de *Google Guava*. En la clase TOTP del ejemplo se obtiene esta *clave secreta* con los métodos <br/> **`byte[]  generateKey()`** y **`String  getSecretKey (byte[] key)`**
<br/><br/>
El método `generateKey()` genera el hash de 20 bytes (160 bits) utilizando el algoritmo **HmacSHA256**. El método `getSecretKey (byte[] key)`, cifra el hash generado, utilizando *Base32*. El resultado es un texto cifrado de 32 bytes (256 bits) al que se le llama **Clave Secreta**.

```java
public static byte[]    generateKey() throws NoSuchAlgorithmException{
    byte[] key = TOTP.getToken();   //---Obtiene una clave aleatoria.
    key = Arrays.copyOf(key, 20);   //---Solamente toma los primeros 20 byte de la clave generada.
    return(key);
}

//---Genera la Clave Secreta a partir del Key proporcionado---
public static String    getSecretKey (byte[] key){
    BaseEncoding base32 = BaseEncoding.base32();
    String secretKey = base32.encode(key);
    return(secretKey);
}
```

```java
//---Devuelve el encoded de la clave generada por generateKey(String algoritmo, int keySize)---
private static  byte[]       getToken() throws NoSuchAlgorithmException{
    return(generateKey("HmacSHA256", 256).getEncoded());
}

//---Genera una clave aleatoria dado el algoritmo y el tamaño deseado de la clave en bits.---
private static  SecretKey    generateKey(String algoritmo, int keySize) throws NoSuchAlgorithmException{
    KeyGenerator kg = KeyGenerator.getInstance(algoritmo);
    SecureRandom sr = new SecureRandom();
    kg.init(keySize, sr);
    SecretKey key = kg.generateKey();
    return(key);
}
```
**Paso 2.** Ingresar la **Clave Secreta** en [Google Authenticator][googleauthtenticator]. <br/>Lo ideal es generar un Código de Barra bidimensional (**QR-Code**) con la *Clave Secreta* que luego pueda ser leida en *Google Authenticator* para mayor facilidad. Para efectos de este ejemplo, se queda así. En otra oportunidad expliclaré como generar el QR-Code.

**Paso 3.** Validar las **Códigos TOTP** que genera [Google Authenticator][googleauthtenticator]. <br/>Para esto debes utilizar el método **`boolean isValidCode(String secretKey, long codeTOTP)`**;  donde **`secretKey`** es la *Clave Secreta* de 32 bytes que fue generada como se explica en el **Paso 1** e instalada en Google Authenticator, **`codeTOTP`** es el *Código TOTP* a validar generado por *Google Authenticator*. El resultado es Verdadero si la *Código TOTP* está vigente y se otiene de la *Clave Secreta*, de lo contrario devuelve *Falso*. En tu aplicación debes tomar las acciones necesarias para cada caso.
```java
//---Valida si un Código TOTP fue generado con la Clave Secreta (seecretKey) y si está vigente---
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
```
[rfc6328]: https://tools.ietf.org/html/rfc6238?fbclid=IwAR0gbgA80ZkOYv5FNtd4B_mQb7rsdrOwkIuDofW8Htw_3xPf1QXvf3iP3zk
[googleauthtenticator]: https://chrome.google.com/webstore/detail/authenticator/bhghoamapcdpbohphigoooaddinpkbai?hl=es
