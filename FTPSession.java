import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Created by Matt on 10/30/15.
 */
public class FTPSession extends Thread {


    protected enum FTPState {User, Auth, Command, Quit}
    protected enum IPState {IPv6, IPv4}

    private static final Logger log = Logger.getLogger("log");
    private static final String FTP_DELEMITER = "\r\n";

    private static final ConcurrentHashMap<Integer, String> FTP_ERRORS = new ConcurrentHashMap<Integer, String>() {{
        put(500, "500 Syntax error, command unrecognized");
        put(501, "501 Syntax error in parameters or arguments");
        put(530, "530 Not logged in");
        put(550, "550 Requested action not taken");
    }};
    protected FTPState state;
    protected IPState ipState;
    protected Socket sessionSocket;
    protected Socket dataSocket;
    protected BufferedReader socketReader;
    protected PrintWriter commandWriter;
    protected String user;
    protected String workingDir;
    protected HashMap<String, String> users;

    /**
     *
     * @param sessionSocket The socket that was accepted from the main thread
     * @param users The hashtable of users that are able to be authenticated
     * @throws IOException
     */
    public FTPSession(Socket sessionSocket, HashMap<String, String> users) throws IOException {
        this.state = FTPState.User;
        this.ipState = getIpAddressType(sessionSocket.getInetAddress());
        this.sessionSocket = sessionSocket;
        this.socketReader = new BufferedReader(new InputStreamReader(sessionSocket.getInputStream()));
        this.commandWriter = new PrintWriter(sessionSocket.getOutputStream(), true);
        this.users = users;
        this.workingDir = System.getProperty("user.dir");
        this.dataSocket = new Socket();
        dataSocket.close();
        log.info("New FTP session initialized at port: " + sessionSocket.getLocalPort() + " On thread " + this.getName());
    }

    /**
     * Runs the ftp instance while the state isnt quitting.
     * preforms endless calls to wait for command until the user quits
     */
    public void run() {
        commandWriter.printf("221 Welcome to Matt's very own FTP server! please login as a valid user!" + FTP_DELEMITER);
        while (this.state != FTPState.Quit) {
            try {
                WaitForCommand();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * The major loops which interprets commands from the user depending on the state of the communication
     *
     * @throws IOException
     */

    protected void WaitForCommand() throws IOException {

        String request = socketReader.readLine();

        ServerSocket passiveServerSocket;
        String[] splitRequest;

        try {
            splitRequest = request.split(" ");
        } catch (NullPointerException e) {
            return;
        }

        //If we are in need of a username from the user
        if (state == FTPState.User) {

            String command = splitRequest[0];

            switch (command) {
                //If they sent a user command
                case "USER": {
                    //Bad arguemnts
                    if (splitRequest.length != 2) {
                        commandWriter.printf("501 Syntax error in parameters or arguments" + FTP_DELEMITER);
                        return;
                    }
                    //not a valid user, change the state
                    if (isValidUser(splitRequest[1])) {
                        commandWriter.printf("331 User " + splitRequest[1] + " accepted, provide password" + FTP_DELEMITER);
                        this.user = splitRequest[1];
                        this.state = FTPState.Auth;
                        return;
                    } else {
                        commandWriter.printf("332 Need an account for login" + FTP_DELEMITER);
                        return;
                    }
                }
                //Help is allowed even when a user is not logged in
                case "HELP": {
                    sendHelp();
                    return;
                }
                //Otherwise let the user know that the command isnt recognized.
                default: {
                    commandWriter.printf("500 Syntax error, command unrecognized" + FTP_DELEMITER);
                }
            }


        } else if (state == FTPState.Auth) {
            //If we are in the authentication statae
            String command = splitRequest[0];

            switch (command) {
                //Only allow the pass command to be sent in.
                case "PASS":
                    if (splitRequest.length != 2) {
                        commandWriter.printf("501 Syntax error in parameters or arguments" + FTP_DELEMITER);
                        return;
                    }
                    if (validatePassword(splitRequest[1])) {
                        commandWriter.printf("230 User has been logged in" + FTP_DELEMITER);
                        log.info("User " + user + " Has been authenticated and logged on");
                        state = FTPState.Command;
                    } else {
                        commandWriter.printf("530 Not logged in, invalid password" + FTP_DELEMITER);
                        log.warning("invalid password entered for user:" + user);
                        state = FTPState.User;
                    }
                    return;
                default:
                    commandWriter.printf("500 Syntax error, command unrecognized" + FTP_DELEMITER);
            }

        } else {
            //Otherwise, we are in the command state, so analize the command
            String command = splitRequest[0];

            switch (command) {
                case "PWD": {
                    //Simply send the current working directory over the command port
                    commandWriter.printf("257 \"" + workingDir + "\" Is the current directory" + FTP_DELEMITER);
                    return;
                }
                case "PASV": {
                    //Give the client a port to connect to if we are in IPv4 mode
                    passiveServerSocket = new ServerSocket(0);
                    if (ipState == IPState.IPv4) {
                        commandWriter.printf("227 Entering passive mode " + generatePasv(passiveServerSocket.getLocalPort()) + FTP_DELEMITER);
                    } else if (ipState == IPState.IPv6) {
                        commandWriter.printf("421 Service not available in ipv6 mode, try EPRT" + FTP_DELEMITER);
                        return;
                    }

                    dataSocket = passiveServerSocket.accept();
                    log.info("Data connection to " + sessionSocket.getInetAddress().getHostAddress() + " initialized");
                    return;
                }
                case "PORT": {
                    if (ipState == IPState.IPv4) {
                        dataSocket = new Socket(sessionSocket.getInetAddress().getHostAddress(), processPort(request));
                        commandWriter.printf("200 PORT command successful" + FTP_DELEMITER);
                        log.info("new data session on thread " + this.getName() + " on port " + dataSocket.getLocalPort());
                        return;
                    } else if (ipState == IPState.IPv6) {
                        //Let the user know that on ipv6 PORT isn't supported
                        commandWriter.printf("421 Service not available in ipv6 mode, try EPRT" + FTP_DELEMITER);
                        return;
                    }
                }
                case "EPSV": {
                    //Get a new server socket from the os, at whatever port
                    passiveServerSocket = new ServerSocket(0);

                    //let the client know which port was chosen
                    commandWriter.printf("229 Entering extended passive mode (|||" + passiveServerSocket.getLocalPort() + "|)" + FTP_DELEMITER);

                    //Accept any connections made to this port
                    dataSocket = passiveServerSocket.accept();
                    log.info("data session initialized on thread " + this.getName() + " on port " + dataSocket.getLocalPort());
                    return;
                }
                case "EPRT": {
                    //Check to make sure that the arguments given are sound
                    if (splitRequest.length < 2) {
                        // Bad arguments
                        commandWriter.printf(FTP_ERRORS.get(501) + FTP_DELEMITER);
                        return;
                    }

                    int activePort;

                    //Process the eprot that was sent to the server, quit if it was bad
                    if ((activePort = processEprt(splitRequest[1])) == -1) {
                        commandWriter.printf("501 Syntax error in parameters or arguments" + FTP_DELEMITER);
                        return;
                    }

                    //Otherwise open up a new socket and let the client know we're ready to connect
                    dataSocket = new Socket(sessionSocket.getInetAddress().getHostAddress(), activePort);
                    commandWriter.printf("200 EPRT command successful" + FTP_DELEMITER);
                    log.info("data session initialized on thread " + this.getName() + " on port " + dataSocket.getLocalPort());
                    return;
                }
                case "LIST": {

                    String listDir = workingDir;

                    //If we have an active data socket
                    if (dataSocket.isConnected()) {

                        if(splitRequest.length > 1){
                            //User has requested a spicific file
                            ArrayList<String> dirList = new ArrayList<>(Arrays.asList(new File(workingDir).list()));

                            //If the current directory list contains the file we want, go ahead and change the directory we are going to send them
                            if (dirList.contains(splitRequest[1]) && new File(workingDir + "/" + splitRequest[1]).isDirectory()){
                                listDir = workingDir + "/" + splitRequest[1];
                            }
                            //Otherwise, let them know that the file wasnt found.
                            else {
                                commandWriter.printf(FTP_ERRORS.get(501) + FTP_DELEMITER);
                                dataSocket.close();
                                return;
                            }

                        }

                        //Let the client know that we are about to send data over
                        commandWriter.printf("150 Opening data connection for " + listDir + FTP_DELEMITER);

                        //Collect information about the current working directory
                        File currentDirectory = new File(listDir);
                        StringBuilder stringBuilder = new StringBuilder();
                        stringBuilder.append("Contents of " + listDir + FTP_DELEMITER);

                        for (File file : currentDirectory.listFiles()) {
                            stringBuilder.append(file.getName() + "\t\t" + (file.isDirectory() ? "Directory" : "File") + FTP_DELEMITER);
                        }

                        //Send the data over the data socket to the client
                        new PrintWriter(dataSocket.getOutputStream(), true).printf(stringBuilder.toString());
                        dataSocket.close();

                        //let the client know that the data send is complete
                        commandWriter.printf("226 Transfer completed" + FTP_DELEMITER);

                        return;
                    } else {
                        //Send over an error that there's no connection
                        commandWriter.printf("425 Can't open data connection" + FTP_DELEMITER);
                        return;
                    }

                }

                case "RETR": {
                    //If we dont have the right amount of arguments, send over an error
                    if (splitRequest.length < 2) {
                        commandWriter.printf(FTP_ERRORS.get(501) + FTP_DELEMITER);
                        return;
                    }

                    //Get the requested file from the request
                    String requestedFile = splitRequest[1];
                    ArrayList<String> currentDirectoryList =new ArrayList<>(Arrays.asList(new File(workingDir).list()));

                    //If the currect directory doesnt contain the file, send a 501 error
                    if (!currentDirectoryList.contains(requestedFile)) {
                        commandWriter.printf(FTP_ERRORS.get(501) + FTP_DELEMITER);
                        dataSocket.close();
                        return;
                    }

                    //if we have an active connection
                    if (dataSocket.isConnected()) {
                        //let the user know that we are about to send data over
                        commandWriter.printf("150 Opening data connection for " + requestedFile + FTP_DELEMITER);

                        //Get the data sockets output stream
                        PrintWriter dataOutput = new PrintWriter(dataSocket.getOutputStream());

                        //Init a file to the path of the file we need to send
                        File file = new File(workingDir + "/" + requestedFile);

                        //Attempt to open, read and send the file over the data
                        try {
                            BufferedInputStream fileReader = new BufferedInputStream(new FileInputStream(workingDir + "/" + requestedFile));
                            byte[] bytes = new byte[(int) file.length()];
                            fileReader.read(bytes, 0, bytes.length);
                            dataSocket.getOutputStream().write(bytes, 0, bytes.length);
                            log.info("file " + file.getName() + " sent to client on thread " + this.getName());
                        }catch (FileNotFoundException e){
                            commandWriter.printf(FTP_ERRORS.get(550) + FTP_DELEMITER);
                            dataSocket.close();
                        }

                        commandWriter.printf("226 Transfer completed" + FTP_DELEMITER);
                        dataSocket.close();
                        return;

                    } else {
                        //Send over an error that there's no connection
                        commandWriter.printf("425 Can't open data connection" + FTP_DELEMITER);
                        return;
                    }
                }

                case "CWD": {

                    ArrayList<String> currentDirectoryList = new ArrayList<>(Arrays.asList(new File(workingDir).list()));
                    String requestedDir = splitRequest[1];

                    //Guard clauses for the directory which is called
                    if (splitRequest.length < 2) {
                        commandWriter.printf(FTP_ERRORS.get(501) + FTP_DELEMITER);
                        return;
                    }
                    if (!currentDirectoryList.contains(requestedDir)) {
                        commandWriter.printf(FTP_ERRORS.get(501) + FTP_DELEMITER);
                        return;
                    }
                    if(!new File(workingDir + "/" + requestedDir).isDirectory()){
                        commandWriter.printf(FTP_ERRORS.get(501) + FTP_DELEMITER);
                        return;
                    }

                    //if all the gaured clauses pass, then change the current directory
                    workingDir += "/" + requestedDir;
                    commandWriter.printf("250 Directory changed" + FTP_DELEMITER);
                    log.info("Current working directory on thread " + this.getName() + " has been changed to " + workingDir);
                    return;

                }
                case "CDUP": {
                    //Get the current direcory, and then call its parent
                    File currentDirectory = new File(workingDir);
                    String tempPath = workingDir;
                    workingDir = currentDirectory.getParent();

                    //If we got a good working dir, go ahead and send it back
                    if (workingDir != null) {
                        commandWriter.printf("250 CDUP command successful" + FTP_DELEMITER);
                        log.info("Current working directory on thread " + this.getName() + " has been changed to " + workingDir);
                        return;
                    }
                    //otherwise just stay where we are and let the user know that it worked
                    else {
                        workingDir = tempPath;
                        commandWriter.printf("250 CDUP command successful" + FTP_DELEMITER);
                        return;
                    }

                }
                case "HELP": {
                    // send the help string when requested
                    sendHelp();
                }

                case "QUIT": {
                    // Quit the session and close all the sockets
                    commandWriter.printf("221 thanks for using my server!" + FTP_DELEMITER);
                    sessionSocket.close();
                    dataSocket.close();
                    state = FTPState.Quit;
                    log.info("Thread " + this.getName() + " has had its session ended by the client");
                    return;
                }

                default: {
                    //Print a 500 error for all other occasions
                    commandWriter.printf(FTP_ERRORS.get(500) + FTP_DELEMITER);
                }
            }
        }
    }

    /**
     * @param eprt the eprt request from the server
     * @return The correct port, if it was a valid eprt, otherwise returns -1
     */
    private int processEprt(String eprt) {

        String[] splitEprt = eprt.split("\\|");

        if (splitEprt[1].equals("1") || splitEprt[1].equals("2")) {
            //one of the correct eprt versions.
            return Integer.parseInt(splitEprt[3]);
        } else {
            return -1;
        }


    }

    /**
     *
     * @param request The PORT request given to the server
     * @return The port that the request gave to the server for interpretation
     */
    private int processPort(String request) {
        String[] splitRequest = request.split(" ");
        String[] portData = splitRequest[1].split(",");

        int p1 = Integer.parseInt(portData[4]);
        int p2 = Integer.parseInt(portData[5]);

        return (p1 * 256) + p2;

    }

    //Checks to see if the given user is valid
    protected boolean isValidUser(String user) {
        return users.containsKey(user);
    }

    //Returns weather or not the given password is valid
    protected boolean validatePassword(String password) {
        if (users.get(user).equals(password)) return true;
        return false;
    }

    /**
     * Sends the help string over the command port
     */
    protected void sendHelp() {
        commandWriter.printf(
                "214- The following commands are recognized."
                + FTP_DELEMITER
                + "USER, PASS, CWD, CDUP, QUIT, PASV, EPSV, PORT, EPRT, RETR, PWD, LIST, HELP"
                + FTP_DELEMITER
        );
    }

    /**
     * @param ipVersion The ipversion of the current socket connection
     * @return The type of IP state that we should use, wheather we are connected with ipv4 or ipv6
     */
    protected IPState getIpAddressType(InetAddress ipVersion) {
        if (ipVersion instanceof Inet6Address) {
            return IPState.IPv6;
        } else if (ipVersion instanceof Inet4Address) {
            return IPState.IPv4;
        }
        return null;
    }

    /**
     *
     * @param serverPort The port created by the server socket
     * @return A valid passive port response
     * @throws IOException
     */
    protected String generatePasv(int serverPort) throws IOException {
        String ipAddress = sessionSocket.getInetAddress().getHostAddress();

        String hexPort = Integer.toHexString(serverPort);
        int p1 = Integer.parseInt(hexPort.substring(0, 2), 16);
        int p2 = Integer.parseInt(hexPort.substring(2, 4), 16);

        return "(" + ipAddress.replace(".", ",") + "," + p1 + "," + p2 + ")";
    }
}
