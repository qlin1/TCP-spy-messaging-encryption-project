/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.net.*;
import java.io.*;
import java.util.Arrays;
import java.util.Scanner;

/**
 *
 * @author linqiaochu 
 * This is a TCP client used by each say in the field.
 */
public class TCPSpyUsingTEAandPasswords {

    public static void main(String args[]) {
        // arguments supply message and hostname
        Socket s = null;
        try {
            int serverPort = 7896;
            s = new Socket(args[1], serverPort);
            DataInputStream in = new DataInputStream(s.getInputStream());
            DataOutputStream out = new DataOutputStream(s.getOutputStream());

            Scanner scanner = new Scanner(System.in);

            //ask the clients to input the information of the key, the userid, password and their location
            System.out.println("Enter symmetric key for TEA (taking first sixteen bytes):");
            String key = scanner.nextLine();
            System.out.print("Enter your ID:");
            String userid = scanner.nextLine();
            System.out.print("Enter your Password:");
            String password = scanner.nextLine();
            System.out.print("Enter your location:");
            String location = scanner.nextLine();

            String info = userid + " " + password + " " + location;

            /* Create a cipher using the first 16 bytes of the passphrase */
            TEA tea = new TEA(key.getBytes()); //Using TEA to encrypt the information

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

        } catch (UnknownHostException e) {
            System.out.println("Socket:" + e.getMessage());
        } catch (EOFException e) {
            System.out.println("EOF:" + e.getMessage());
        } catch (IOException e) {
            System.out.println("readline:" + e.getMessage());
        } finally {
            if (s != null) {
                try {
                    s.close();
                } catch (IOException e) {
                    System.out.println("close:" + e.getMessage());
                }
            }
        }
    }
}
