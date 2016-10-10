package com.allinpay.io.ssl;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;

/**
 * This class demonstrates constructing and customizing the
 * TrustStore. It loads a truststore called "clientTrust" with
 * password "password" - but allows this to be altered by the
 * command-line.
 */
class CustomTrustStoreClient extends CustomKeyStoreClient
{
  private final String DEFAULT_TRUSTSTORE=com.allinpay.io.ssl.SimpleSSLServer.KEY_PATH+"clientTrust";
  private final String DEFAULT_TRUSTSTORE_PASSWORD="password";

  private String trustStore=DEFAULT_TRUSTSTORE;
  private String trustStorePassword=DEFAULT_TRUSTSTORE_PASSWORD;

  /**
   * Overrides main() in SimpleSSLClient to use the
   * CustomTrustStoreClient.
   */
  public static void main(String args[])
  {
    CustomTrustStoreClient client=new CustomTrustStoreClient();
    client.runClient(args);
    client.close();
  }

  /**
   * Overrides the version in SimpleSSLClient to handle the -ts and
   * -tspass arguments.
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

      // We deal with "-ts" and "-tspass" here; other strings
      // are passed up to the superclass.
      if (arg.equals("-TS")) {
        trustStore=args[i+1];
        out=2;
      }
      else if (arg.equals("-TSPASS")) {
        trustStorePassword=args[i+1];
        out=2;
      }
      else out=super.handleCommandLineOption(args,i);
    }
    catch(Exception e) {
      // Something went wrong with the command-line parse.
      out=0;
    }

    return out;
  }

  /**
   * Displays the command-line usage for this client.
   */
  protected void displayUsage()
  {
    super.displayUsage();
    System.out.println("\t-ts\ttruststore (default '"
                       +DEFAULT_TRUSTSTORE+"', JKS format)");
    System.out.println("\t-tspass\ttruststore password (default '"
                       +DEFAULT_TRUSTSTORE_PASSWORD+"')");
  }  

  /**
   * Provides a SSLSocketFactory which ignores JSSE's choice of truststore,
   * and instead uses either the hard-coded filename and password, or those
   * passed in on the command-line.
   * This method calls out to getTrustManagers() to do most of the
   * grunt-work. It actally just needs to set up a SSLContext and obtain
   * the SSLSocketFactory from there.
   * @return SSLSocketFactory SSLSocketFactory to use
   */
  protected SSLSocketFactory getSSLSocketFactory()
    throws IOException, GeneralSecurityException
  {
    // Call getTrustManagers to get suitable trust managers
    TrustManager[] tms=getTrustManagers();
    
    // Call getKeyManagers (from CustomKeyStoreClient) to get suitable
    // key managers
    KeyManager[] kms=getKeyManagers();

    // Next construct and initialise a SSLContext with the KeyStore and
    // the TrustStore. We use the default SecureRandom.
    SSLContext context=SSLContext.getInstance("SSL");
    context.init(kms, tms, null);

    // Finally, we get a SocketFactory, and pass it to SimpleSSLClient.
    SSLSocketFactory ssf=context.getSocketFactory();
    return ssf;
  }

  /**
   * Returns an array of TrustManagers, set up to use the required
   * trustStore. This is pulled out separately so that later  
   * examples can call it.
   * This method does the bulk of the work of setting up the custom
   * trust managers.
   * @param trustStore the TrustStore to use. This should be in JKS format.
   * @param password the password for this TrustStore.
   * @return an array of TrustManagers set up accordingly.
   */
  protected TrustManager[] getTrustManagers()
    throws IOException, GeneralSecurityException
  {
    // First, get the default TrustManagerFactory.
    String alg=TrustManagerFactory.getDefaultAlgorithm();
    TrustManagerFactory tmFact=TrustManagerFactory.getInstance(alg);
    
    // Next, set up the TrustStore to use. We need to load the file into
    // a KeyStore instance.
    FileInputStream fis=new FileInputStream(trustStore);
    KeyStore ks=KeyStore.getInstance("jks");
    ks.load(fis, trustStorePassword.toCharArray());
    fis.close();

    // Now we initialise the TrustManagerFactory with this KeyStore
    tmFact.init(ks);

    // And now get the TrustManagers
    TrustManager[] tms=tmFact.getTrustManagers();
    return tms;
  }
}
