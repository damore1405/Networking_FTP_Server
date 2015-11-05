import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;
import java.util.logging.*;

public class Server {

    protected static HashMap<String,String> validUsers = populateUsers();
    static Logger log;

    public static void main(String[] args) {

        ServerSocket serverSocket = null;
        int socket = 21;
        ArrayList<FTPSession> currentSessions = new ArrayList<>();
        FTPSession session;

        switch (args.length){
            case 1: {
                socket = 21;
                try {
                    log = initLogger(args[0]);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                break;
            }
            case 2: {
                try {
                    socket = Integer.parseInt(args[1]);
                    log = initLogger(args[0]);
                } catch (NumberFormatException e) {
                    System.err.println("invalid port given! exiting...");
                    log.severe("invalid port given! exiting...");
                    System.exit(1);
                } catch (IOException ioE) {
                    ioE.printStackTrace();
                }
                break;
            }
            default: {
                System.err.println("invalid arg Count! exiting...");
                System.exit(1);
                break;
            }

        }

        try {
            serverSocket = new ServerSocket(socket);
        } catch (IOException e) {
            System.err.println("Port not available!");
            System.exit(1);
        }

        while (true) {
            try {
                Socket connection = serverSocket.accept();
                session = new FTPSession(connection, validUsers);
                currentSessions.add(new FTPSession(connection, validUsers));
                session.start();
            } catch (IOException e) {
                break;
            }

        }

    }

    /**
     * Initialises the log to the correct format and file for use throughout the threads.
     * @param filepath
     * @return an initialized log to the appropriate file
     * @throws IOException
     */

    protected static Logger initLogger(String filepath) throws IOException {
        Logger log = Logger.getLogger("log");
        FileHandler fh = new FileHandler(filepath, true);
        SimpleFormatter formatter = new SimpleFormatter();
        fh.setFormatter(formatter);
        log.addHandler(fh);
        log.setUseParentHandlers(false);

        return log;
    }

    /**
     *
     * @return A hashmap of the valid users from the CSV file in the directory in which the server was run
     */
    protected static HashMap<String,String> populateUsers() {
        try {
            Scanner userScanner = new Scanner(new File("/Users/Matt/Git Repos/mdamore_hw2b/src/users.csv"));

            HashMap<String, String> userMap = new HashMap<>();

            while (userScanner.hasNextLine()){
                String[] userPassSplit = userScanner.nextLine().split(",");
                userMap.put(userPassSplit[0], userPassSplit[1]);
            }

            return userMap;
        }
        catch (FileNotFoundException e){
            System.err.println("No valid users file found! exiting...");
            log.info("No valid users file found!");
            System.exit(1);
        }

        return null;
    }
}
