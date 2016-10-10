package com.allinpay.io.ssl;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

/**
 * This class demonstrates constructing and customizing the
 * KeyStore. It loads a keystore called "clientKeys" with
 * password "password" - but allows this to be altered by the
 * command-line.
 */
class CustomKeyStoreClient extends SimpleSSLClient
{
  private final String DEFAULT_KEYSTORE=com.allinpay.io.ssl.SimpleSSLServer.KEY_PATH+"clientKeys";
  private final String DEFAULT_KEYSTORE_PASSWORD="password";

  private String keyStore=DEFAULT_KEYSTORE;
  private String keyStorePassword=DEFAULT_KEYSTORE_PASSWORD;

  /**
   * Overrides main() in SimpleSSLClient to use the
   * CustomKeyStoreClient.
   */
  public static void main(String args[])
  {
    CustomKeyStoreClient client=new CustomKeyStoreClient();
    client.runClient(args);
    client.close();
  }

  /**
   * Overrides the version in SimpleSSLClient to handle the -ks and
   * -kspass arguments.
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

      // We deal with "-ks" and "-kspass" here; other strings
      // are passed up to the superclass.
      if (arg.equals("-KS")) {
        keyStore=args[i+1];
        out=2;
      }
      else if (arg.equals("-KSPASS")) {
        keyStorePassword=args[i+1];
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
    System.out.println("\t-ks\tkeystore (default '"
                       +DEFAULT_KEYSTORE+"', JKS format)");
    System.out.println("\t-kspass\tkeystore password (default '"
                       +DEFAULT_KEYSTORE_PASSWORD+"')");
  }

  /**
   * Provides a SSLSocketFactory which ignores JSSE's choice of keystore,
   * and instead uses either the hard-coded filename and password, or those
   * passed in on the command-line.
   * This method calls out to getKeyManagers() to do most of the
   * grunt-work. It actally just needs to set up a SSLContext and obtain
   * the SSLSocketFactory from there.
   * @return SSLSocketFactory SSLSocketFactory to use
   */
  protected SSLSocketFactory getSSLSocketFactory()
    throws IOException, GeneralSecurityException
  {
    // Call getKeyManagers to get suitable key managers
    KeyManager[] kms=getKeyManagers();

    // Now construct a SSLContext using these KeyManagers. We
    // specify a null TrustManager and SecureRandom, indicating that the
    // defaults should be used.
    SSLContext context=SSLContext.getInstance("SSL");
    context.init(kms, null, null);

    // Finally, we get a SocketFactory, and pass it to SimpleSSLClient.
    SSLSocketFactory ssf=context.getSocketFactory();
    return ssf;
  }

  /**
   * Returns an array of KeyManagers, set up to use the required
   * keyStore. This is pulled out separately so that later  
   * examples can call it.
   * This method does the bulk of the work of setting up the custom
   * trust managers.
   * @param trustStore the KeyStore to use. This should be in JKS format.
   * @param password the password for this KeyStore.
   * @return an array of KeyManagers set up accordingly.
   */
  protected KeyManager[] getKeyManagers()
    throws IOException, GeneralSecurityException
  {
    // First, get the default KeyManagerFactory.
    String alg=KeyManagerFactory.getDefaultAlgorithm();
    KeyManagerFactory kmFact=KeyManagerFactory.getInstance(alg);
    
    // Next, set up the KeyStore to use. We need to load the file into
    // a KeyStore instance.
    FileInputStream fis=new FileInputStream(keyStore);
    KeyStore ks=KeyStore.getInstance("jks");
    ks.load(fis, keyStorePassword.toCharArray());
    fis.close();

    // Now we initialise the KeyManagerFactory with this KeyStore
    kmFact.init(ks, keyStorePassword.toCharArray());

    // And now get the KeyManagers
    KeyManager[] kms=kmFact.getKeyManagers();
    return kms;
  }
}
