package com.allinpay.io.ssl;

import javax.net.ssl.*;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;

/**
 * This class demonstrates a technique for selecting the alias
 * from the KeyStore to use. It obtains a set of KeyManagers (as
 * in the other examples) and wraps these in a custom KeyManager
 * implementation. The custom implementation lets the 'real' KeyManager
 * do most of the real work, but intercepts its choice of alias.
 */
public class SelectAliasClient extends CustomTrustStoreClient
{
  private String alias=null;

  /**
   * Overrides main() in SimpleSSLClient to use the
   * SelectAliasClient.
   */
  public static void main(String args[])
  {
    SelectAliasClient client=new SelectAliasClient();
    client.runClient(args);
    client.close();
  }

  /**
   * Overrides the version in SimpleSSLClient to handle the -alias
   * argument.
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

      // We deal with "-alias" here; other strings are passed up
      // to the superclass.
      if (arg.equals("-ALIAS")) {
        alias=args[i+1];
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
   * Displays the command-line usage for this client.
   */
  protected void displayUsage()
  {
    super.displayUsage();
    System.out.println("\t-alias\talias to use");
  }

  /**
   * Provides a SSLSocketFactory which can ignore JSSE's choice of truststore,
   * keystore and alias. For truststore and keystore, uses either the
   * hard-coded filename and password, or those supplied on the command-line.
   * For alias, uses either JSSE's choice or the alias supplied on the
   * command-line.
   * This method calls getKeyManagers() from CustomKeyStoreClient and
   * getTrustManagers from CustomTrustStoreClient to load the appropriate
   * keystore and truststore. It then wraps the returned KeyManagers in
   * the AliasForcingKeyManager class, which ensures the correct alias
   * is chosen.
   * @return SSLSocketFactory SSLSocketFactory to use
   */
  protected SSLSocketFactory getSSLSocketFactory()
    throws IOException, GeneralSecurityException
  {
    // Call the superclasses to get suitable trust and key managers
    KeyManager[] kms=getKeyManagers();
    TrustManager[] tms=getTrustManagers();

    // If the alias has been specified, wrap recognised KeyManagers
    // in AliasForcingKeyManager instances.
    if (alias!=null) {
      for (int i=0; i<kms.length; i++) {
        // We can only deal with instances of X509KeyManager
        if (kms[i] instanceof X509KeyManager)
          kms[i]=new AliasForcingKeyManager((X509KeyManager)kms[i], alias);
      }
    }

    // Now construct a SSLContext using these (possibly wrapped)
    // KeyManagers, and the TrustManagers. We still use a null
    // SecureRandom, indicating that the defaults should be used.
    SSLContext context=SSLContext.getInstance("SSL");
    context.init(kms, tms, null);

    // Finally, we get a SocketFactory, and pass it to SimpleSSLClient.
    SSLSocketFactory ssf=context.getSocketFactory();
    return ssf;
  }

  /**
   * AliasForcingKeyManager is an implementation of X509KeyManager which
   * wraps an existing X509KeyManager instance, and forces use of a
   * particular alias. If the requested alias is not permissable, the
   * connection is not allowed to proceed.
   */
  private class AliasForcingKeyManager implements X509KeyManager
  {
    X509KeyManager baseKM=null;
    String alias=null;

    /**
     * @param keyManager the X509KeyManager to wrap
     * @param alias the alias to force
     */
    public AliasForcingKeyManager(X509KeyManager keyManager, String alias)
    {
      baseKM=keyManager;
      this.alias=alias;
    }

    /**
     * chooseClientAlias selects an alias to authenticate the client side
     * of a SSL connection. This implementation uses getClientAliases to
     * find a list of valid aliases and checks the requested alias against
     * this list. If the requested alias is valid, it is returned; otherwise
     * null is returned.
     * See the J2SE javadoc for a fuller explanation of this call.
     * @param keyType the key algorithm type name(s)
     * @param issuers the list of acceptable CA issuer subject names
     * @param socket the socket to be used for this connection.
     */
    public String chooseClientAlias(String[] keyType, Principal[] issuers,
                                    Socket socket)
    {
      // For each keyType, call getClientAliases on the base KeyManager
      // to find valid aliases. If our requested alias is found, select it
      // for return.
      boolean aliasFound=false;

      for (int i=0; i<keyType.length && !aliasFound; i++) {
        String[] validAliases=baseKM.getClientAliases(keyType[i], issuers);
        if (validAliases!=null) {
          for (int j=0; j<validAliases.length && !aliasFound; j++) {
            if (validAliases[j].equals(alias)) aliasFound=true;
          }
        }
      }

      if (aliasFound) return alias;
      else return null;
    }

    // The other methods simply drop through to the base KeyManager.

    public String chooseServerAlias(String keyType, Principal[] issuers,
                                    Socket socket)
    {
      return baseKM.chooseServerAlias(keyType, issuers, socket);
    }

    public X509Certificate[] getCertificateChain(String alias)
    {
      return baseKM.getCertificateChain(alias);
    }

    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
      return baseKM.getClientAliases(keyType, issuers);
    }

    public PrivateKey getPrivateKey(String alias)
    {
      return baseKM.getPrivateKey(alias);
    }

    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
      return baseKM.getServerAliases(keyType, issuers);
    }
  }
}
