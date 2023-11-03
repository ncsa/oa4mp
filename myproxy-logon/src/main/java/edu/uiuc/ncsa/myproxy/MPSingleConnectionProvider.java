package edu.uiuc.ncsa.myproxy;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.ConnectionException;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.crypto.MyPKCS10CertRequest;

import javax.net.ssl.KeyManagerFactory;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

/**
 * Creates a single {@link MyProxyConnectable} object for a given configuration.
 * Generally this is used internally by the {@link MPConnectionProvider} class.
 * <p>Created by Jeff Gaynor<br>
 * on 1/23/14 at  9:38 AM
 */
public class MPSingleConnectionProvider<T extends MyProxyConnectable> implements javax.inject.Provider<T> {
    String username;
    String hostname;
    String password;
    int port;
    long socketTimeout = 0L;
    long lifetime;// note this must be converted to seconds for MyProxy!
    KeyManagerFactory keyManagerFactory;
    MyLoggingFacade facade;
    String serverDN;


    public MPSingleConnectionProvider(MyLoggingFacade logger,
                                      String username,
                                      String password,
                                      long lifetime,
                                      MyProxyServiceFacade facade
    ) throws IOException, GeneralSecurityException {
        this(logger, username, password, null, lifetime, facade);
    }

    public MPSingleConnectionProvider(MyLoggingFacade logger,
                                      String username,
                                      String password,
                                      String loa,
                                      long lifetime,
                                      MyProxyServiceFacade facade
    ) throws IOException, GeneralSecurityException {
        this(logger,
                username,
                password,
                facade.getFacadeConfiguration().getHostname(),
                facade.getLOAPort(loa),
                lifetime,
                facade.getFacadeConfiguration().getSocketTimeout(),
                facade.getKeyManagerFactory(),
                facade.getFacadeConfiguration().getServerDN());
    }


    public MPSingleConnectionProvider(MyLoggingFacade logger,
                                      String username,
                                      String password,
                                      String hostname,
                                      int port,
                                      long lifetime,
                                      long socketTimeout,
                                      KeyManagerFactory keyManagerFactory,
                                      String serverDN) {
        this.username = username;
        if (password == null) {
            this.password = "";
        } else {
            this.password = password;
        }
        this.port = port;
        this.lifetime = lifetime;
        this.hostname = hostname;
        this.keyManagerFactory = keyManagerFactory;
        this.facade = logger;
        this.socketTimeout = socketTimeout;
        this.serverDN = serverDN;
    }

    public static class MyProxyLogonConnection implements MyProxyConnectable {
        @Override
        public boolean isReadOnly() {
            return false;
        }

        @Override
        public void setReadOnly(boolean readOnly) {

        }

        public MyProxyLogonConnection(MyProxyLogon myProxyLogon) {
            this.myProxyLogon = myProxyLogon;
        }

        @Override
        public void setLifetime(long certLifetime) {
            if (myProxyLogon != null) {
                int newLifetime = (int) (certLifetime / 1000);
                if (myProxyLogon.getLifetime() != newLifetime) {
                    // only go to the trouble of resetting this and re-acquiring the connection if there is a change.
                    myProxyLogon.setLifetime(newLifetime);
                    if (myProxyLogon.isConnected()) {
                        close();
                        open();
                    }
                }
            }
        }

        public MyProxyLogon getMyProxyLogon() {
            return myProxyLogon;
        }

        MyProxyLogon myProxyLogon;


        @Override
        public void close() {
            try {
                if (myProxyLogon.isConnected()) {
                    myProxyLogon.disconnect();
                }
            } catch (Throwable e) {
                throw new ConnectionException(" disconnecting from myproxy", e);
            }

        }

        @Override
        public void open() {
            try {
                myProxyLogon.connect();
                myProxyLogon.logon();
            } catch (Throwable e) {
                throw new ConnectionException(" connecting to myproxy", e);
            }
        }

        @Override
        public String toString() {
            String out = getClass().getSimpleName() + "[";
            if (myProxyLogon == null) {
                out = out + "(no myproxy logon)";
            } else {
                out = out + "lifetime=" + myProxyLogon.getLifetime() +
                        ", port=" + myProxyLogon.getPort() +
                        ", host=" + myProxyLogon.getHost();
            }
            return out + "]";
        }

        public LinkedList<X509Certificate> getCerts(byte[] pkcs10CertRequest) {
            try {
                myProxyLogon.getCredentials(pkcs10CertRequest);
                LinkedList<X509Certificate> certList = new LinkedList<X509Certificate>();
                certList.addAll(myProxyLogon.getCertificates());
                return certList;
            } catch (Throwable e) {
                throw new GeneralException(" getting certs from myproxy \"" + e.getMessage() + "\"", e);
            }

        }

        @Override
        public LinkedList<X509Certificate> getCerts(MyPKCS10CertRequest pkcs10CertRequest) {
            return getCerts(pkcs10CertRequest.getEncoded());
        }
        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        String description;

        Identifier identifier;

        @Override
        public Identifier getIdentifier() {
            return identifier;
        }

        @Override
        public String getIdentifierString() {
            if (identifier == null) return null;
            return identifier.toString();
        }

        @Override
        public void setIdentifier(Identifier identifier) {
            this.identifier = identifier;
        }

        @Override
        public Identifiable clone() {
            return null;
        }
    } //end inner class

    @Override
    public T get() {
        MyProxyLogon myProxyLogon = null;
        if (facade == null) {
            myProxyLogon = new MyProxyLogon();
        } else {
            myProxyLogon = new MyProxyLogon(facade, serverDN);
        }
        myProxyLogon.setHost(hostname);
        // Fix for CIL-153, CIL-147
        myProxyLogon.setLifetime((int) (lifetime / 1000));
        myProxyLogon.setPort(port);
        myProxyLogon.setSocketTimeout(socketTimeout);
        myProxyLogon.setUsername(username);
        myProxyLogon.setPassphrase(password);
        myProxyLogon.setKeyManagerFactory(keyManagerFactory);
        return (T) new MyProxyLogonConnection(myProxyLogon);
    }

}
