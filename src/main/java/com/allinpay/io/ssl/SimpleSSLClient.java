package com.allinpay.io.ssl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * A very simple client which forges an SSL connection to a remote
 * server. Text entered into stdin is forwarded to the server.
 * By default, uses 'localhost' and port 8087, although these are
 * configurable on the command-line.
 * The client needs to be stopped with Ctrl-C.
 */
public class SimpleSSLClient
{
  private static final String DEFAULT_HOST="localhost";

  private SSLSocket socket;
  private String host=DEFAULT_HOST;
  private int port=com.allinpay.io.ssl.SimpleSSLServer.DEFAULT_PORT;

  /**
   * main() method, called when run from the command-line.
   * Constructs a SimpleSSLClient object and calls runClient on
   * it. Should be overridden by subclasses to construct the
   * correct form of client object.
   */
  public static void main(String args[])
  {
    SimpleSSLClient client=new SimpleSSLClient();
    client.runClient(args);
    client.close();
  }
  
  /**
   * Intended to be overridden. Deals with one argument. If the
   * argument is unrecognised, can call the super method.
   * @param args Array of strings.
   * @param i array cursor.
   * @return number of successfully handled arguments, zero if an
   * error was encountered.
   */
  protected int handleCommandLineOption(String[] args, int i)
  {
    int out;
    try {
      String arg=args[i].trim().toUpperCase();

      // The "-port" and "-host" arguments are supported. There
      // is no super method to call if we encounter a different
      // argument.
      if (arg.equals("-PORT")) {
        port=Integer.parseInt(args[i+1]);
        out=2;
      }
      else if (arg.equals("-HOST")) {
        host=args[i+1];
        out=2;
      }
      else out=0;
    }
    catch(Exception e) {
      // Something went wrong with the command-line parse.
      out=0;
    }

    return out;
  }

  /**
   * Intended to be overridden. Provides the SSLSocketFactory to
   * be used for this client. The default implementation returns
   * the JVM's default SSLSocketFactory.
   * @return SSLSocketFactory SSLSocketFactory to use
   */
  protected SSLSocketFactory getSSLSocketFactory()
    throws IOException, java.security.GeneralSecurityException
  {
    return (SSLSocketFactory)SSLSocketFactory.getDefault();
  }

  /**
   * Displays the command-line usage for this client. Should be
   * overridden if getSSLSocketFactory is.
   */
  protected void displayUsage()
  {
    System.out.println("Options:");
    System.out.println("\t-host\thost of server (default '"+DEFAULT_HOST+"')");
    System.out.println("\t-port\tport of server (default "+com.allinpay.io.ssl.SimpleSSLServer.DEFAULT_PORT+")");
  }  


  /**
   * runClient() deals with command-line parameters, and then runs
   * the client to send text from stdin to the server. Calls
   * handleCommandLineOption() and getSSLSocketFactory() to allow
   * subclasses to customize behaviour.
   * @param args command-line arguments.
   */
  public void runClient(String args[])
  {
    // Parse the command-line
    boolean parseFailed=false;
    int i=0;
    while (i<args.length && !parseFailed) {
      // We pass, to handleCommandLineOption, the entire array
      // of arguments and the position of the cursor.
      // It returns the number of successfully handled arguments,
      // or zero if an error was encountered.
      int handled=handleCommandLineOption(args, i);
      if (handled==0) parseFailed=true;
      else i+=handled;
    }
    
    if (parseFailed) {
      // Something went wrong with the command-line parse.
      // A real application would issue a good error message;
      // we'll just display our usage.
      displayUsage();
    }
    else {
      try {
        // The command-line parse succeeded. Now connect using the
        // correct SSLSocketFactory.
        SSLSocketFactory ssf=getSSLSocketFactory();
        connect(ssf);
        System.out.println("Connected, now you call input: ");
        
        // We connected successfully, now transmit text from stdin.
        transmit(System.in);
      }
      catch (IOException ioe) {
        // Connect failed.
        System.out.println("Connection failed: "+ioe);
      }
      catch (java.security.GeneralSecurityException gse) {
        // Connect failed.
        System.out.println("Connection failed: "+gse);
      }        
    }
  }

  /**
   * Connects to the server, using the supplied SSLSocketFactory.
   * Returns only after the SSL handshake has been completed.
   * @param sf the SocketFactory to use.
   * @exception IOException if the connect failed.
   */
  public void connect(SSLSocketFactory sf) throws IOException
  {
    socket=(SSLSocket)sf.createSocket(host, port);

    try {
      socket.startHandshake();
    }
    catch (IOException ioe) {
      // The handshake failed. Close the socket.
      try {
        socket.close();
      }
      catch (IOException ioe2) {
        // Ignore this; throw on the original error.
      }
      socket=null;
      throw ioe;
    }
  }

  /**
   * Transmits the supplied InputStream. connect() must have been
   * successfully called before calling transmit. Loops until
   * interrupted (Ctrl-C), end of the stream (Ctrl-D), or until
   * a network error is encountered.
   * @param in the InputStream to transmit. It is converted to UTF-8
   * for transmission to the server.
   */
  public void transmit(InputStream in)
  {
    try {
      // Set up a reader from the InputStream (probably stdin).
      // The InputStreamReader uses the JVM's default codepage to interpret
      // the raw bytes; the BufferedReader splits the input into lines for us.
      BufferedReader reader=new BufferedReader(new InputStreamReader(in));

      // Set up a writer to the socket. We use UTF-8 to represent text; this
      // matches the server. The JVM really should support UTF-8 - if it
      // doesn't we'll fall back to the JVM's default codepage.
      Writer writer;
      try {
        writer=new OutputStreamWriter(socket.getOutputStream(), "UTF-8");
      }
      catch (UnsupportedEncodingException uee) {    
        System.out.println("Warning: JVM cannot support UTF-8. Using default instead");
        writer=new OutputStreamWriter(socket.getOutputStream());
      }
      
      // Now read the input line-by-line, and send it to the socket.
      boolean done=false;
      while (!done) {
        String line=reader.readLine();
        if (line!=null) {
          writer.write(line);
          writer.write('\n');
          writer.flush();
        }
        else done=true;
      }
    }
    catch (IOException ioe) {
      // Log the error and exit
      System.out.println("Error: "+ioe);
    }

    // Close the socket, ignoring any errors.
    try {
      socket.close();
    }
    catch (IOException ioe) {}
  }

  /**
   * Disconnects from the server.
   */
  public void close()
  {
    try {
      if (socket!=null) socket.close();
    }
    catch (IOException ioe) {
      // Ignore this - there's not much we can do.
    }
    socket=null;
  }
}
