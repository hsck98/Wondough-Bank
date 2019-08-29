//Client server
//The client includes two methods of reading entries from the console:

//The method obtained from the CS258 Module called "readEntry()" which allows input in the console to be read. This is the default reading method used.

//Then, there is the imported method from the java.io.Console packet which allows entries to be read whilst keeping the input hidden during insertion in the console. This is only used for reading passwords whilst ensuring that other individuals around the machine (other than the customer) can't see it.

//The client server initially (after creating the session and establishing a connection with the web server) prints out a menu in the console with 3 options: register, login or exit. The customer can then insert either number 1, 2 or 0. The input is sanitized so that only these 3 integers are the possible input, therefore removing a possible injection of code. In the case an invalid input is introduced an error message is sent to the user console and the menu is presented again.

//The client then reads the entries and calls the corresponding method according to the input value.

//The register() method asks the customer for their details such as username, password and email. He/She is also asked to introduce the password a second time just in case the password was introduced wrongly in the first place. These four strings are then gathered into a JsonObject object along with an extra initial field called "Type" to allow the server side to recognize what this data is for. There are three type options "registration", "login" and "code". The object can then be converted into a single string to be sent across to the web server.

//The login() method does essentially the same thing as the register() method except it only requires two fields to be inputted, those being: the username and the password; and the "Type" field is "login".


import java.util.*;
import java.sql.*;
import java.io.*;
import javax.net.ssl.*;
import java.security.KeyStore;
import javax.json.*;
import java.io.Console;

public class Client {
  private String host = "127.0.0.1";
  private int port = 9999;

  public static void main(String[] args) throws SQLException, IOException {
      Client client = new Client();
      client.run();
  }

  Client() {
  }

  Client(String host, int port) {
      this.host = host;
      this.port = port;
  }

  // Create the and initialize the SSLContext
  private SSLContext createSSLContext() {
      try {
          KeyStore keyStore = KeyStore.getInstance("JKS");
          keyStore.load(new FileInputStream("keystore.jks"),"password".toCharArray());

          // Create key manager
          KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
          keyManagerFactory.init(keyStore, "password".toCharArray());
          KeyManager[] km = keyManagerFactory.getKeyManagers();

          // Create trust manager
          TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
          trustManagerFactory.init(keyStore);
          TrustManager[] tm = trustManagerFactory.getTrustManagers();

          // Initialize SSLContext
          SSLContext sslContext = SSLContext.getInstance("TLSv1");
          sslContext.init(km,  tm, null);

          return sslContext;
      } catch (Exception e) {
          e.printStackTrace();
      }

      return null;
  }

  // Start to run the server
  public void run() {
      SSLContext sslContext = this.createSSLContext();

      try {
          // Create socket factory
          SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
          // Create socket

          SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(this.host, this.port);

          System.out.println("SSL client started");
          new ClientThread(sslSocket).start();
      } catch (Exception e) {
          e.printStackTrace();
      }
  }

  // Thread handling the socket to server
  static class ClientThread extends Thread {
      private SSLSocket sslSocket = null;

      ClientThread(SSLSocket sslSocket){
          this.sslSocket = sslSocket;
      }

      public void run() {
          sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

          try {
              // Start handshake
              sslSocket.startHandshake();

              // Get session after the connection is established
              SSLSession sslSession = sslSocket.getSession();

              System.out.println("SSLSession :");
              System.out.println("\tProtocol : "+sslSession.getProtocol());
              System.out.println("\tCipher suite : "+sslSession.getCipherSuite());

              // Start handling application content
              InputStream inputStream = sslSocket.getInputStream();
              OutputStream outputStream = sslSocket.getOutputStream();
              BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
              PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));

              boolean done = false;
              do {
                printMenu();
                String ch = readEntry("Enter your choice: ");
                String line = null;
                switch (ch.charAt(0)) {
                  case '1': String register = register();
                            printWriter.println(register);
                            printWriter.flush();
                            while((line = bufferedReader.readLine()) != null) {
                              System.out.println(line);
                              break;
                            }
                  break;
                  case '2': String login = login();
                            printWriter.println(login);
                            printWriter.flush();
                            while((line = bufferedReader.readLine()) != null) {
                              System.out.println(line);
                              if (line.equals("A code has been sent to your email: ")) {
                                printWriter.println(enterCode());
                                printWriter.flush();
                                while((line = bufferedReader.readLine()) != null) {
                                  System.out.println(line);
                                  if (line.equals("Successful login")) {
                                    printAccountMenu();
                                    done = true;
                                  }
                                  break;
                                }
                              }
                              break;
                            }
                  break;
                  case '0': printWriter.println("Exit");
                            printWriter.flush();
                            done = true;
                  break;
                  default : System.out.println(" Not a valid option ");
                }
              } while(!done);

              sslSocket.close();
          } catch (Exception e) {
              e.printStackTrace();
          }
      }
  }

  private static String readEntry(String prompt) {
    try {
      StringBuffer buffer = new StringBuffer();
      System.out.print(prompt);
      System.out.flush();
      int c = System.in.read();
      while(c != '\n' && c != -1) {
        buffer.append((char)c);
        c = System.in.read();
      }
      return buffer.toString().trim();
    }
    catch (IOException e) {
      return "";
    }
  }

  private static void printMenu() {
    System.out.println("\n MENU:");
    System.out.println("(1) Register");
    System.out.println("(2) Log in");
    System.out.println("(0) Quit. \n");
  }

  private static void printAccountMenu() {
    System.out.println("\n Welcome Back");
    System.out.println("(1) View Transactions");
    System.out.println("(2) Contact Customer Service");
    System.out.println("(0) Log out.");
    System.out.println("Enter your choice: \n");
  }

  private static String register() {
    Console cnsl = null;
    String username = readEntry("Enter an account username: ");
    char[] passwordChar = null;
    char[] repeatPasswordChar = null;
    // String password = readEntry("Enter password: ");
    // String repeatPassword = readEntry("Repeat password: ");
    try {
      cnsl = System.console();
      passwordChar = cnsl.readPassword("Enter an account password, it must contain a minimum of eight characters, at least one uppercase letter, one lowercase letter, one number and one special character: ");
      repeatPasswordChar = cnsl.readPassword("Repeat password: ");
    } catch (Exception e) {
      System.out.println("Error reading registration passwords");
    }
    String password = String.valueOf(passwordChar);
    String repeatPassword = String.valueOf(repeatPasswordChar);
    String email = readEntry("Enter an email: ");
    JsonObject customer = Json.createObjectBuilder()
      .add("Type", "registration")
      .add("Username", username)
      .add("Password", password)
      .add("RepeatPassword", repeatPassword)
      .add("Email", email)
      .build();
    String customerText = customer.toString();
    return customerText;
  }

  private static String login() {
    Console cnsl = null;
    String username = readEntry("Enter username: ");
    char[] passwordChar = null;
    // String password = readEntry("Enter password: ");
    try {
      cnsl = System.console();
      passwordChar = cnsl.readPassword("Enter password: ");
    } catch (Exception e) {
      System.out.println("Error reading login password");
    }
    String password = String.valueOf(passwordChar);
    JsonObject user = Json.createObjectBuilder()
      .add("Type", "login")
      .add("Username", username)
      .add("Password", password)
      .build();
    String userText = user.toString();
    return userText;
  }

  public static String enterCode() {
    String enteredCode = readEntry("Please enter code here: ");
    JsonObject code = Json.createObjectBuilder()
      .add("Type", "code")
      .add("Code", enteredCode)
      .build();
    String codeText = code.toString();
    return codeText;
  }
}
