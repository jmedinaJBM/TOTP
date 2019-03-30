# Autenticación de 2 Factores Java
La Autenticación de 2 Factores (**2FA** por sus siglas en inglés), es un mecanismo para asegurar la identidad del usuario con el fin de proteger sus recursos. Los grandes de la Industria de TI como las Redes Sociales y Bancos utilizan este mecanismo, muy efectivo y sencillo de implementar en todo tipo de aplicaciones. Está basado en la Tecnología **TOTP**, *Time-based One Time Password*, por sus siglas en inglés, es un estandar definido en el [RFC 6328][rfc6328].
<br/><br/>
Cuando accedemos a nuestros recursos, lo hacemos tradicionalmente con un usuario y contraseña, que se supone solo nosotros conocemos. Pero qué pasa si alguien averigua nuestro usuario y contraseña? La solución es añadir un elemento más de seguridad. Algunos lo conocen como Token, pero técnicamente se le conoce como Clave de Una Vez Basada en el Tiempo, TOTP por sus siglas en inglés. Significa que solamente la podrás utilizar una vez, que tiene un tiempo de caducidad y que es generada en función del tiempo.

## TOTP
Es el estandar que sirve para implementar 2FA. Consiste en utilizar el SmartPhone con una aplicación que genera las Claves que deberás proporcionar a la aplicación que quieres acceder, posterior a que hayas ingresado tu Usuario y Contraseña. Google Authenticator es una App de Google que genera Claves TOTP, es gratuita y está disponible para Android y iOS.<br/><br/>

Para incorporar en una aplicación Java, este segundo Factor (**2FA**), sea de escritorio o web, es necesario hacer lo siguiente:
1. Implementar lo que dice el [RFC 6328][rfc6328]. En el ejmplo he creado una clase llamada TOTP con los métodos correspondientes. 
2. Instalar Google Authenticator en un SmartPhone (Android o iOS).
3. Generar una Clave Secreta e instalarla en Google Authenticator. En el ejemplo hay métodos desarrollados.
4. Verificar la Clave TOTP generada por Google Authenticator. En el ejemplo hay un método desarrollado.

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
**Paso 1.** Generar una Clave Secreta para *Google Authenticator*; esta clave secreta es un hash de 20 byte (160 bits) que se debe cifrar en Base32. La clave resultante de 32 byte (256 bits), es la que debes registrar para un usuario específico; se debe generar una clave secreta para cada usuario. Para este cifrado utilizo la librería de Google Guava. En la clase TOTP del ejemplo se implementa con los métodos `byte[]  generateKey()` y `String  getSecretKey (byte[] key)
`

[rfc6328]: https://tools.ietf.org/html/rfc6238?fbclid=IwAR0gbgA80ZkOYv5FNtd4B_mQb7rsdrOwkIuDofW8Htw_3xPf1QXvf3iP3zk
