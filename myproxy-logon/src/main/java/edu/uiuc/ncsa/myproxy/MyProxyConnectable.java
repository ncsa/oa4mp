package edu.uiuc.ncsa.myproxy;

import edu.uiuc.ncsa.security.core.cache.Cacheable;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;

import java.security.cert.X509Certificate;
import java.util.LinkedList;

/**
 * <H3>Lifecycle</H3>
 * These are produced by the {@link MyProxyServiceFacade}. The actual workings of the implementation will have all the required
 * configuration in place to perform all required operations.
 * <p>Created by Jeff Gaynor<br>
 * on 1/23/14 at  9:25 AM
 */
public interface MyProxyConnectable extends Cacheable{
    /**
     * Establish a connection to a Myproxy server.
     */
    public void open();

    /**
     * Ends the connection to the MyProxy server cleanly
     */
    public void close();

    /**
     * Retrieves a collection of certificates. Note this this is an ordered list since
     * order matters in some context.
     * @return
     */
    public LinkedList<X509Certificate> getCerts(MyPKCS10CertRequest pkcs10CertRequest);

    public LinkedList<X509Certificate> getCerts(byte[] pkcs10CertRequest);

    public void setLifetime(long certLifetime);
}
