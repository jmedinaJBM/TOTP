
package com.jbm.pruebas.otp;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Ejemplo de Autenticación de 2 Factores con Google Authenticator. 
 * @author Jairo Medina
 */
public class TOTPSample {
    
    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException, IOException {
        
        //String secretKey = "2MIGXQ3JHVU2ONEZI6WHHXIDCTPZAJ2M";
        String secretKey = TOTP.getSecretKey();
        
        System.out.print("Secret Key for Google Authenticator: ");
        System.out.println(TOTP.getFormatedKey(secretKey)+"\n");
        
        do{
            System.out.print("Ingrese codigo TOTP:  ");
            byte[] value = new byte[10];
            System.in.read(value);
            
            value = Arrays.copyOf(value, TOTP.PASS_CODE_LENGTH);
            String strValue = (new String(value)).trim();
            
            Long longValue = Long.parseLong(strValue);
            
            boolean result = TOTP.isValidCode(secretKey, longValue);
            System.out.println("Result-> "+result);
        }while(true);
    }
    
}
