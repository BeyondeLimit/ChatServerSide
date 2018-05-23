import javax.crypto.Cipher;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.sql.*;
import java.util.Properties;

import static jdk.nashorn.internal.objects.NativeString.substring;

public class Server implements Runnable{

    private List<ServerClient> clients = new ArrayList<ServerClient>();
    private List<Integer> clientResp = new ArrayList<Integer>();

    private int port;
    private DatagramSocket socket;

    private Thread thrdRun,thrdManage,thrdSend,thrdRecieve;
    private boolean running;

    private PrivateKey privateKey;
    private static PublicKey pubKey;

    private final int MAX_ATTEMPTS = 5;
    public Server(int port){
        this.port = port;
        try {
            socket = new DatagramSocket(port);
        }catch(SocketException e){
            e.printStackTrace();
            return;
        }
        thrdRun = new Thread(this,"Server");
        thrdRun.start();
        }
        public void run(){
            running = true;
            System.out.println("Server started on port " + port);
            dBinfo();
            manageClient();
            recieveData();
            try {
                crypto();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private void manageClient(){
            thrdManage = new Thread("Manage"){
                public void run(){
                    while(running){     //Managing
                    //System.out.println(clients.size()); // check current clients amount
                       sendToAll("/a/ping");
                        try {
                            thrdManage.sleep(3000);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                        for(int i = 0;i <clients.size();i++){
                           ServerClient sc = clients.get(i);
                           if(!clientResp.contains(sc.getID())){
                                if(sc.attempt >= MAX_ATTEMPTS){
                                    disconnect(sc.getID(),false);
                                }else{
                                    sc.attempt++;
                                }
                           }else{
                               clientResp.remove(new Integer(sc.getID()));
                               sc.attempt = 0;
                           }
                       }

                    }
                }
            };
            thrdManage.start();
        }

        private void recieveData(){
            thrdRecieve = new Thread("Recieve"){
                public void run(){
                    while(running){
                        byte[] data = new byte[1024];
                        DatagramPacket packet = new DatagramPacket(data, data.length);
                        try {
                            socket.receive(packet);
                            packet.getAddress();
                            packet.getPort();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        try {
                            process(packet);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        //System.out.println(clients.get(0).address.toString() + " : " + clients.get(0).port);
                    }
                }
            };
            thrdRecieve.start();
        }
        private void sendToAll(String message) {
                for (int i = 0; i < clients.size(); i++) {
                    ServerClient client = clients.get(i);
                    send(message.getBytes(), client.address, client.port);
            }
        }
        private void send (final byte[] data, final InetAddress address, final int port){
            thrdSend = new Thread("Send"){
                public void run(){
                    DatagramPacket packet = new DatagramPacket(data,data.length,address,port);
                    try {
                        socket.send(packet);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            };
            thrdSend.start();
        }

        private void send(String message, InetAddress adress, int port){
            message += "/e/";
            send(message.getBytes(),adress,port);
        }
        private void process (DatagramPacket packet) throws Exception{
            String line = new String(packet.getData());
            if(line.startsWith("/c/")){
                //UUID id = UUID.randomUUID();
                int id = UniqueID.getID();
                System.out.println("Curr id is : " + id);
                clients.add(new ServerClient(line.substring(3,line.length()),packet.getAddress(),packet.getPort(),id));
                String ID = "/c/" + id;
                send(ID,packet.getAddress(),packet.getPort());
                String given = "/k/" + Base64.getEncoder().encodeToString(pubKey.getEncoded());
                send(given.trim().getBytes(),packet.getAddress(),packet.getPort());
            }else if (line.startsWith("/d/")) {
                String id = line.split("/d/|/e/")[1];
                disconnect(Integer.parseInt(id), true);
            } else if (line.startsWith("/a/")) {
                clientResp.add(Integer.parseInt(line.split("/a/|/e/")[1]));
            }else {
                String tempProtoc = substring(line,0,3);
                //System.out.println(tempProtoc);
                line = line.substring(3);
                line = line.trim();
                byte[] decMess = Base64.getDecoder().decode(line);
                byte[] derepted = decrypt(privateKey,decMess);
                String decTry = new String(derepted);
                if (tempProtoc.startsWith("/n/")) {
                    decTry = "/n/" + decTry;
                    sendToAll(decTry);
                }  else {
                    System.out.println(line);
                }
            }
        }
        private void disconnect(int id, boolean status){
            ServerClient cl = null;
            for (int i = 0; i < clients.size();i++){
                if(clients.get(i).getID() == id){
                    cl = clients.get(i);
                    clients.remove(i);
                    break;
                }
            }
            String mess = "";
            if(status){
                mess = "Client : " + cl.name.trim() + " , (" + cl.getID() + ") @ " + cl.address.toString() + " : " + cl.port + " disconnected";
            }else{
                mess = "Client : " + cl.name.trim() + " , (" + cl.getID() + ") @ " + cl.address.toString() + " : " + cl.port + " timed out";
            }
            System.out.println(mess);
            try {
                sendToAll(mess);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        public static byte[] decrypt(PrivateKey privateKey,byte[]message)throws Exception{
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            return cipher.doFinal(message);
        }


    public  void crypto()throws Exception{
        KeyPair keyPair = buildKeyPair();
        pubKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }


    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {

        final int keySize = 650;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    public void dBinfo(){
        try {
            Class.forName("org.postgresql.Driver");
            String url = "jdbc:postgresql://localhost:3307/chatDB";
            Connection conn = DriverManager.getConnection(url, "postgres","Agruikwjdxa1234");
            Statement stm = conn.createStatement();
            ResultSet res = stm.executeQuery("select * from messages");
            while(res.next()) {
                System.out.println(res.getInt(1) + res.getString(2) + res.getString(3));
            }
            conn.close();
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
