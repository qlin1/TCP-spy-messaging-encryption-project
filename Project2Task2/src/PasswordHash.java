
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author linqiaochu
 * PasswordHash to calculate the hashed password of the client together the salt
 */
public class PasswordHash {
    
    /**
     * computePasswordHash calculate the hashed password of the client together the salt
     * @param inputtext the String that need to be computed
     * @return result the hashed password
     */
    public String computePasswordHash(String inputtext){
        String result = "";
        try {
                //Use the MD5 to compute hashes
                MessageDigest messageDigest =MessageDigest.getInstance("MD5");
                byte[] inputByteArray = inputtext.getBytes();
                messageDigest.update(inputByteArray);
                byte[] resultByteArray = messageDigest.digest();
                
                //convert the result into hex text
                result = javax.xml.bind.DatatypeConverter.printHexBinary(resultByteArray);
                
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(PasswordHash.class.getName()).log(Level.SEVERE, null, ex);
            }
        return result;
    }
    
    /**
     * main method computes the hashed password together with the given salt for the 3 spies
     */
    public static void main(String[] args){
        PasswordHash ph = new PasswordHash();
        
        String p1 = "c11083b4b0a7743a"+"james";
        String p2 = "08eac03b80adc33d"+"joe";
        String p3 = "e4ba5cbd251c98e6"+"mike"; 
        
        String hashp1=ph.computePasswordHash(p1);
        String hashp2=ph.computePasswordHash(p2);
        String hashp3=ph.computePasswordHash(p3);
        
        System.out.println("Hashed password1: "+hashp1);
        System.out.println("Hashed password2: "+hashp2);
        System.out.println("Hashed password3: "+hashp3);
    }
}
