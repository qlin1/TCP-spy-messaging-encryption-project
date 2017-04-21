/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

/**
 *
 * @author linqiaochu This is a TCP client used by each say in the field.
 */
public class TCPSpyUsingTEAandPasswordsAndRSA {

    public static void main(String args[]) {
        // arguments supply message and hostname
        Socket s = null;

        // Each public and private key consists of an exponent and a modulus
        BigInteger n = new BigInteger("4303726723427976965106092685266183861027806240495038073401965119485715044342685019996107355288765911065561026845647482250699284032087736252675338983928901123979758622694376413742813201250163960484545008020606738807615885832170216143507413743"); // n is the modulus for both the private and public keys
        BigInteger e= new BigInteger("65537"); // e is the exponent of the public key
        
        try {
            int serverPort = 7896;
            s = new Socket(args[0], serverPort);
            DataInputStream in = new DataInputStream(s.getInputStream());
            DataOutputStream out = new DataOutputStream(s.getOutputStream());

            Scanner scanner = new Scanner(System.in);

            //ask the clients to input the information of the key, the userid, password and their location
//            System.out.println("Enter symmetric key for TEA (taking first sixteen bytes):");
//            String key = scanner.nextLine();
            System.out.print("Enter your ID:");
            String userid = scanner.nextLine();
            System.out.print("Enter your Password:");
            String password = scanner.nextLine();
            System.out.print("Enter your location:");
            String location = scanner.nextLine();

            String info = userid + " " + password + " " + location;

            Random rnd = new Random();
            BigInteger key = new BigInteger(16 * 8, rnd);

            BigInteger c = key.modPow(e, n);
            byte[] rsaKey = c.toByteArray();
//            String test1 = new String(rsaKey);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    
//            System.out.println(test1);
            
            out.write(rsaKey);
            out.flush();

            /* Create a cipher using the first 16 bytes of the passphrase */
            TEA tea = new TEA(key.toByteArray()); //Using TEA to encrypt the information

            //change the original information into byte type
            byte[] original = info.getBytes();

            /* Run it through the cipher... and back */
            byte[] crypt = tea.encrypt(original);
            byte[] result = tea.decrypt(crypt);

            /* Ensure that all went well */
            String test = new String(result);
            if (!test.equals(info)) {
                throw new RuntimeException("Fail");
            }

            //output the encrypted information to the socket
            out.write(crypt);
            out.flush();

            //get the information that server sent back to the client in the socket
            String data = in.readUTF();
            System.out.println(data);

        } catch (UnknownHostException ex) {
            System.out.println("Socket:" + ex.getMessage());
        } catch (EOFException ex) {
            System.out.println("EOF:" + ex.getMessage());
        } catch (IOException ex) {
            System.out.println("readline:" + ex.getMessage());
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (IOException ex) {
                    System.out.println("close:" + ex.getMessage());
                }
            }
        }
    }
}
