//Both the client server and the web server connect to the same SSL socket under the same localhost and port number. When both programs run, a single server thread is created through which they exchange data. In order to make sure that data is less vulnerable to "man-in-the-middle" attacks it is always encrypted. To do this, a keystore is created along with a private key for the bank. The keystore is then loaded with a FileInputStream object (which contains the data to be sent) and a password to the keystore. Upon reception of the data, the other server decrypts the data in the file.

//Moving onto the actual methods that allows us to exchange data. Two objects are created called BufferedReader and PrintWriter. The BufferedReader object allows data that has already been sent to its current input stream file to be read. The PrintWriter places the desired information in the output stream file and sends it to the other server's input stream.

//The web server focuses on analyzing the data in the input stream file and performing the correct SQL statements depending on the customer's needs. By using the JsonReader object, the string read from the input file can be converted back to a JsonObject object.

//By looking at the "Type" field, the server is able to determine which method to call:

//Registration: When registering each data piece is validated before creating an account with those details. The entries in the database are checked to see if there are any accounts with the username or email desired. The password is checked against a pattern created from a regex expression which is configured to match only if the string has at least 8 characters, one upper case, one lower case letter and one special character. The repeated password is checked with the original password to see if they are equal. In the case, any of these data validate, the appropriate error message is sent to the client server.
//Once all the data has been validated, a random code of 6 digits is generated and an email is sent to the customer through a Bank gmail account. The purpose of this code is to verify that the user is indeed entering his own details rather than someone else's, so when the customer recieves the code, he/she introduces it in the client console and sends it back to the web server (so here) and the code entered by the user is checked against the code generated. If they match, the two factor authentication is complete and the final step of registration can be done.
//Finally, the passwords are salted and hashed before being stored in the database. The salt is created using the SecureRandom object with the "SHA1PRNG" algorithm to generate 16 random bytes. The hashing function involves two things: creating a SecretKeyFactory object using the "PBKDF2WithHmacSHA1" algorithm and creating a password-based-encrytion spec over 1000 iteration. A byte array is created by generating a secret from the SecretKeyFactory using the spec. Both the salt and the hash are then converted into hexadecimal form and combined into a single string to produce the hashed password.
//The data to be stored in the database are the customer id (primary key so already predetermined), username, hashed password, salt and email.

//Login: when logging in the username is checked within the database for its existence. If it exists, then the corresponding hashed password and its salt are retrieved. The salt is converted back to byte form from hexadecimal form and the password the customer introduced is hashed once again using exactly the same method. If the resulting password is the same as the hashed password that was stored in the database, the customer is allowed access, otherwise access is denied and an error message is sent to the client server.

//Another security features includes the use of preparedStatements in order to prevent SQL injections from the user side.

import java.io.*;
import java.util.*;
import java.sql.*;
import javax.json.*;
import javax.mail.*;
import javax.mail.internet.*;
import javax.net.ssl.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.KeyStore;
import java.io.FileNotFoundException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;

public class Server {
  private int port = 9999;
  private boolean isServerDone = false;
  static byte[] storeSalt = new byte[16];
  static String otp = null;

  public static void main(String[] args) {
      Server server = new Server();
      server.run();
  }

  Server() {
  }

  Server(int port){
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

      try{
          // Create server socket factory
          SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

          // Create server socket
          SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(this.port);

          System.out.println("SSL server started");
          while(!isServerDone){
              SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();

              // Start the server thread
              new ServerThread(sslSocket).start();
          }
      } catch (Exception e) {
          e.printStackTrace();
      }
  }

  // Thread handling the socket from client
  static class ServerThread extends Thread {
      private SSLSocket sslSocket = null;

      ServerThread(SSLSocket sslSocket) {
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

              Connection conn = getConnection();

              String line = null;
              String username = null;
              String password = null;
              String repeatPassword = null;
              String email = null;

              while ((line = bufferedReader.readLine()) != null) {
                System.out.println(line);
                if (line.equals("Exit")) {
                  break;
                } else {
                  JsonReader jsonReader = Json.createReader(new StringReader(line));
                  JsonObject customer = jsonReader.readObject();
                  if (customer.getString("Type").equals("registration")) {
                    username = customer.getString("Username");
                    password = customer.getString("Password");
                    repeatPassword = customer.getString("RepeatPassword");
                    email = customer.getString("Email");
                    registerServer(conn, username, password, repeatPassword, email, printWriter);
                  } else if (customer.getString("Type").equals("login")) {
                    username = customer.getString("Username");
                    password = customer.getString("Password");
                    loginServer(conn, username, password, printWriter);
                  } else if (customer.getString("Type").equals("code")) {
                    String enteredCode = customer.getString("Code");
                    if (enteredCode.equals(otp)) {
                      printWriter.println("Successful login");
                      printWriter.flush();
                    }
                  }
                  jsonReader.close();
                }
                if(line.trim().isEmpty()) {
                  break;
                }
              }
              printWriter.print("HTTP/1.1 200\r\n");
              printWriter.flush();
              conn.close();
              sslSocket.close();
          } catch (Exception e) {
              e.printStackTrace();
          }
      }
  }

  public static Connection getConnection() {
    Connection c = null;

     try {
        Class.forName("org.sqlite.JDBC");
        c = DriverManager.getConnection("jdbc:sqlite:WondoughBank.db");
     } catch ( Exception e ) {
        System.err.println( e.getClass().getName() + ": " + e.getMessage() );
        System.exit(0);
     }
     System.out.println("Opened database successfully");
     return c;
  }

  public static void registerServer(Connection conn, String username, String password, String repeatPassword, String email, PrintWriter printWriter) throws SQLException {
    String usernameCheckSQL = "SELECT * FROM Customers WHERE Username = ?;";
    PreparedStatement usernameStmt = conn.prepareStatement(usernameCheckSQL);
    usernameStmt.setString(1, username);
    try {
      ResultSet containsUsername = usernameStmt.executeQuery();
      if(containsUsername.next()) {
        printWriter.println("Username already exists");
        printWriter.flush();
      } else {
        String regex =  "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[$@$!%*?&])[A-Za-z\\d$@$!%*?&]{8,}";
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(password);
        if (!(m.matches())) {
          printWriter.println("Password must contain a minimum of eight characters, at least one uppercase letter, one lowercase letter, one number and one special character");
          printWriter.flush();
        } else {
          if (!repeatPassword.equals(password)) {
            printWriter.println("Passwords do not match!");
            printWriter.flush();
          } else {
            String emailCheckSQL = "SELECT * FROM Customers WHERE Email = ?;";
            PreparedStatement emailStmt = conn.prepareStatement(emailCheckSQL);
            emailStmt.setString(1, email);
            try {
              ResultSet containsEmail = emailStmt.executeQuery();
              if(containsEmail.next()) {
                printWriter.println("There already exists an account under that email");
                printWriter.flush();
              } else {
                storeAccount(conn, username, password, email, printWriter);
              }
              emailStmt.close();
            } catch (SQLException e) {
              System.out.println("Error 2");
            }
          }
        }
      }
      usernameStmt.close();
    } catch (SQLException e) {
      System.out.println("Error 1");
    }
  }

  public static void loginServer(Connection conn, String username, String password, PrintWriter printWriter) throws SQLException, NoSuchAlgorithmException {

    String usernameCheckSQL = "SELECT Password, Salt, Email FROM Customers WHERE username = ?;";
    PreparedStatement usernameStmt = conn.prepareStatement(usernameCheckSQL);
    usernameStmt.setString(1, username);
    try {
      ResultSet accountRs = usernameStmt.executeQuery();
      if (accountRs.next()) {
        String storedPassword = accountRs.getString(1);
        String storedSaltString = accountRs.getString(2);
        String email = accountRs.getString(3);
        byte[] storedSalt = storedSaltString.getBytes();
        try {
          if (validatePassword(password, storedPassword)) {
            String from = "WondoughBankAuthentication";
            String pass = "Lifegood98";
            String[] to = {email}; // list of recipient email addresses
            String subject = "One Time Code";
            String body = "Please enter the following code into the terminal: " + otpGenerator();
            sendFromGMail(from, pass, to, subject, body);
            printWriter.println("A code has been sent to your email: ");
            printWriter.flush();
          } else {
            printWriter.println("Wrong password");
            printWriter.flush();
          }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
          System.out.println("Error 6");
        }
      } else {
        printWriter.println("There is no account with this username");
        printWriter.flush();
      }
      usernameStmt.close();
    } catch (SQLException e) {
      System.out.println("Error 7");
    }
  }

  private static String hash(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
    int iterations = 1000;
    char[] passwordChars = password.toCharArray();

    PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, iterations, 64*8);
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    byte[] hash = skf.generateSecret(spec).getEncoded();
    String hashedPassword = iterations + ":" + toHex(salt) + ":" + toHex(hash);
    return hashedPassword;
  }

  private static boolean validatePassword(String originalPassword, String storedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
      String[] parts = storedPassword.split(":");
      int iterations = Integer.parseInt(parts[0]);
      byte[] salt = fromHex(parts[1]);
      byte[] hash = fromHex(parts[2]);

      PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt, iterations, hash.length * 8);
      SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      byte[] testHash = skf.generateSecret(spec).getEncoded();

      int diff = hash.length ^ testHash.length;
      for(int i = 0; i < hash.length && i < testHash.length; i++) {
          diff |= hash[i] ^ testHash[i];
      }
      return diff == 0;
  }

  private static byte[] getSalt() throws NoSuchAlgorithmException {
    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
    byte[] salt = new byte[16];
    sr.nextBytes(salt);
    return salt;
  }

  private static String toHex(byte[] array) throws NoSuchAlgorithmException {
    BigInteger bi = new BigInteger(1, array);
    String hex = bi.toString(16);
    int paddingLength = (array.length * 2) - hex.length();
    if (paddingLength > 0) {
        return String.format("%0"  +paddingLength + "d", 0) + hex;
    } else {
        return hex;
    }
  }

  private static byte[] fromHex(String hex) throws NoSuchAlgorithmException {
     byte[] bytes = new byte[hex.length() / 2];
     for(int i = 0; i < bytes.length ;i++) {
         bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
     }
     return bytes;
 }

 private static String otpGenerator() {
   int otpInt = (int) Math.floor(Math.random()*1000000);
   otp = Integer.toString(otpInt);
   return otp;
 }

 private static void sendFromGMail(String from, String pass, String[] to, String subject, String body) {
       Properties props = System.getProperties();
       String host = "smtp.gmail.com";
       props.put("mail.smtp.starttls.enable", "true");
       props.put("mail.smtp.host", host);
       props.put("mail.smtp.user", from);
       props.put("mail.smtp.password", pass);
       props.put("mail.smtp.port", "587");
       props.put("mail.smtp.auth", "true");

       Session session = Session.getDefaultInstance(props);
       MimeMessage message = new MimeMessage(session);

       try {
           message.setFrom(new InternetAddress(from));
           InternetAddress[] toAddress = new InternetAddress[to.length];

           // To get the array of addresses
           for( int i = 0; i < to.length; i++ ) {
               toAddress[i] = new InternetAddress(to[i]);
           }

           for( int i = 0; i < toAddress.length; i++) {
               message.addRecipient(Message.RecipientType.TO, toAddress[i]);
           }

           message.setSubject(subject);
           message.setText(body);
           Transport transport = session.getTransport("smtp");
           transport.connect(host, from, pass);
           transport.sendMessage(message, message.getAllRecipients());
           transport.close();
       }
       catch (AddressException ae) {
           ae.printStackTrace();
       }
       catch (MessagingException me) {
           me.printStackTrace();
       }
   }

   private static void storeAccount(Connection conn, String username, String password, String email, PrintWriter printWriter) throws SQLException {
     try {
       storeSalt = getSalt();
     } catch (NoSuchAlgorithmException e) {
       System.out.println("Error 3");
     }
     String hashedPassword = null;
     try {
       hashedPassword = hash(password, storeSalt);
     } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
       System.out.println("Error 4");
     }
     String accountSQL = "INSERT INTO Customers VALUES(NULL, ?, ?, ?, ?);";
     PreparedStatement insertAccountStmt = conn.prepareStatement(accountSQL);
     insertAccountStmt.setString(1, username);
     insertAccountStmt.setString(2, hashedPassword);
     insertAccountStmt.setString(3, storeSalt.toString());
     insertAccountStmt.setString(4, email);
     try {
       insertAccountStmt.executeUpdate();
       insertAccountStmt.close();
       printWriter.println("Account successfully created");
       printWriter.flush();
     } catch (SQLException e) {
       System.out.println("Error 5");
     }
   }
}
