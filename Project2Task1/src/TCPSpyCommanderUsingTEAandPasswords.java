/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.net.*;
import java.io.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Scanner;
import java.util.Set;

/**
 *
 * @author linqiaochu 
 * This is the TCP server used by Spy Commander Beggs.
 */
public class TCPSpyCommanderUsingTEAandPasswords {

    public static void main(String args[]) {
        try {
            int serverPort = 7896; // the server port
            ServerSocket listenSocket = new ServerSocket(serverPort);

            //Ask the spy commander about the symmetric key
            System.out.println("Enter symmetric key for TEA (taking first sixteen bytes):");
            Scanner scanner = new Scanner(System.in);
            String serverKey = scanner.nextLine();
            System.out.println("Waiting for spies to visit…");

            //create a hash map to store the initial location information of the spies
            //the initial locations for all the spies are Hamburg Hall
            HashMap<String, String> hmapl = new HashMap<String, String>();
            hmapl.put("jamesb", "-79.945389,40.444216,0.00000");
            hmapl.put("joem", "-79.945389,40.444216,0.00000");
            hmapl.put("mikem", "-79.945389,40.444216,0.00000");

            while (true) {
                Socket clientSocket = listenSocket.accept();
                //create an instance of connection by giving clientsocket,
                //the serverkey that commander gave and the hashmap of clients'initial location information
                Connection c = new Connection(clientSocket, serverKey, hmapl);
            }
        } catch (IOException e) {
            System.out.println("Listen socket:" + e.getMessage());
        }
    }
}

/**
 * class Connection which extends the Thread class
 */
class Connection extends Thread {

    DataInputStream in;
    DataOutputStream out;
    Socket clientSocket;

    //count used for storing the number of the client access
    public static int count = 1;
    //serverkey used for storing the symmetric key that the commander gave
    public static String serverKey = "";
    //hmapl used for getting and storing the location information for clients
    HashMap<String, String> hmapl = new HashMap<String, String>();

    /**
     * Connection constructor for class Connection
     *
     * @param aClientSocket
     * @param key
     * @param hmap
     */
    public Connection(Socket aClientSocket, String key, HashMap hmap) {
        try {
            clientSocket = aClientSocket;
            serverKey = key;
            hmapl = hmap;
            in = new DataInputStream(clientSocket.getInputStream());
            out = new DataOutputStream(clientSocket.getOutputStream());
            this.start();
        } catch (IOException e) {
            System.out.println("Connection:" + e.getMessage());
        }
    }

    /**
     * run override method contains most of the operations
     */
    public void run() {
        try {			                 // an echo server
            //create a hash map to store the hashed passwords of each spy
            HashMap<String, String> hmap = new HashMap<String, String>();
            hmap.put("jamesb", "CF2D0FA6402DC4B35AA0E1DEBC4D8833");
            hmap.put("joem", "31CA53B4CAE808DA7D94B1AD642D77C4");
            hmap.put("mikem", "1E51F64ADC42A65EEBEC4DF88812BDFD");
            Set keyset = hmap.keySet(); //Create a set for the userids

            //create a hash map to store the salt regarding each spy
            HashMap<String, String> hmapSalt = new HashMap<String, String>();
            hmapSalt.put("jamesb", "c11083b4b0a7743a");
            hmapSalt.put("joem", "08eac03b80adc33d");
            hmapSalt.put("mikem", "e4ba5cbd251c98e6");

            /* Create a cipher using the first 16 bytes of the passphrase */
            TEA tea = new TEA(serverKey.getBytes());

            //create a buffer byte[] of 100 bytes
            byte[] b = new byte[100];
            //get the number of bytes the client has sent to the server
            int numOfData = in.read(b);

            //make a copy of the recieved data into the array of certain bytes
            byte[] dataByte = Arrays.copyOf(b, numOfData);
            byte[] result = tea.decrypt(dataByte);
            String info = new String(result);

            //split the received data into userid, password and location information
            String[] message = info.split(" ");
            String returnmessage = "";

            //check whether the decrypte data is all ASCII code or not
            //if not, it means that the symmetric key that the client sent is not correct, then server send back an exception message to the client
            if (!isASCII(info)) {
                System.out.println("Got visit " + count + " illegal symmetric key used. This may be an attack.");
                returnmessage = "Exception: Invalid key is being used!";
            } else {   //if the symmetric key is correct, then check the userid and the password
                PasswordHash ph = new PasswordHash();

                //call the computePasswordHash method to calculate the hashed password
                String password = ph.computePasswordHash(hmapSalt.get(message[0]) + message[1]);

                //when the userid and password are all correct, update the location information for this client
                if (keyset.contains(message[0]) && hmap.get(message[0]).equals(password)) {
                    System.out.println("Got visit " + count + " from " + message[0]);
                    hmapl.put(message[0], message[2]);
                    returnmessage = "Thank you. Your location was securely transmitted to Intelligence Headquarters.";
                } else {
                    //when the userid or password is not correct, ignore the access and return the invalid message
                    System.out.println("Got visit " + count + " from " + message[0] + ". Illegal Password attempt. This may be an attack.");
                    returnmessage = "Not a valid user-id or password.";
                }
            }

            //write the return message into sockect
            out.writeUTF(returnmessage);
            //increase user access number by one
            count++;

            //create the kml file, add the updated client location information into the file
            String kmlfile = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
                    + "<kml xmlns=\"http://earth.google.com/kml/2.2\"\n"
                    + "><Document>\n"
                    + "<Style id=\"style1\">\n"
                    + "<IconStyle>\n"
                    + "<Icon>\n"
                    + "<href>http://maps.gstatic.com/intl/en_ALL/mapfiles/ms/micons/blue- dot.png</href>\n"
                    + "</Icon> </IconStyle> </Style> <Placemark>\n"
                    + "<name>seanb</name>\n"
                    + "<description>Spy Commander</description> <styleUrl>#style1</styleUrl>\n"
                    + "<Point>\n"
                    + "<coordinates>-79.945289,40.44431,0.00000</coordinates> </Point>\n"
                    + "</Placemark> <Placemark>\n"
                    + "<name>jamesb</name> <description>Spy</description> <styleUrl>#style1</styleUrl> <Point>\n"
                    + "<coordinates>" + hmapl.get("jamesb") + "</coordinates> </Point>\n"
                    + "</Placemark>\n"
                    + "<Placemark> <name>joem</name> <description>Spy</description> <styleUrl>#style1</styleUrl> <Point>\n"
                    + "<coordinates>" + hmapl.get("joem") + "</coordinates> </Point>\n"
                    + "</Placemark>\n"
                    + "<Placemark> <name>mikem</name> <description>Spy</description> <styleUrl>#style1</styleUrl> <Point>\n"
                    + "<coordinates>" + hmapl.get("mikem") + "</coordinates> </Point>\n"
                    + "</Placemark>\n"
                    + "</Document>\n"
                    + "</kml>";

            //write the kml text into kml file
            FileWriter fw = new FileWriter("SecretAgents.kml");
            fw.write(kmlfile);
            fw.flush();
            fw.close();

        } catch (EOFException e) {
            System.out.println("EOF:" + e.getMessage());
        } catch (IOException e) {
            System.out.println("readline:" + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {/*close failed*/

            }
        }

    }

    /**
     * isASCII the method to check if all the characters in the string are ASCII code
     * @param s refers to the String that needs to be checked
     * @return boolean if the string is all ASCII letters, return true, otherwise return false
     */
    public boolean isASCII(String s) {
        for (char c : s.toCharArray()) {
            if (((int) c) > 127) {
                return false;
            }
        }
        return true;
    }
}
