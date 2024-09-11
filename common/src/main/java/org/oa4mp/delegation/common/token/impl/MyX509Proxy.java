package org.oa4mp.delegation.common.token.impl;

import org.oa4mp.delegation.common.token.MyX509Certificates;
import edu.uiuc.ncsa.security.util.crypto.CertUtil;
import edu.uiuc.ncsa.security.util.crypto.KeyUtil;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;


/**
 * A proxy extension class capable of storing the private key as well next to the certificates
 * <p>Created by Tamas Balogh<br>
 */
public class MyX509Proxy extends MyX509Certificates {

    protected PrivateKey proxyKey;

   /*  For use with CANL libraries. Include dependency for Crypt8 5.4-CANL.
   public MyX509Proxy(byte[] pemProxy) {
        super(ProxyUtil.certificatesFromProxy(pemProxy));
        this.proxyKey = ProxyUtil.keyFromProxy(pemProxy);
    }*/

    public MyX509Proxy(MyX509Certificates certs, PrivateKey key) {
        super(certs.getX509Certificates());
        this.proxyKey = key;
    }

    public MyX509Proxy(X509Certificate[] certs, PrivateKey key) {
        super(certs);
        this.proxyKey = key;
    }

    public PrivateKey getProxyKey() {
        return proxyKey;
    }

    /**
     * Return the Proxy Certificate complete with. This method will include the
     * proxy Private Key into the second place in the PEM formatted certificate chain
     *
     * @return the Proxy Certificate in PEM format
     * @throws CertificateEncodingException In case the certificate data is corrupt
     */
    public String getX509ProxyPEM() throws CertificateEncodingException {

        String pem = "";

        if ( x509Certificates.length > 0 ) {
            pem += CertUtil.toPEM(x509Certificates[0]) + "\n";
        }

        if ( proxyKey != null ) {
            pem += KeyUtil.toPKCS8PEM(proxyKey) + "\n";
        }

        for (int i = 1; i < x509Certificates.length; ++i){
            pem += CertUtil.toPEM(x509Certificates[i]) + "\n";
        }
        return pem;

    }

    /*
    @Override
    public String getX509CertificatesPEM() throws CertificateEncodingException {
        String pem = "";
        for (int i = 0; i < x509Certificates.length; ++i){
            pem += CertUtil.toPEM(x509Certificates[i]) + "\n";
        }
        return pem;
    }
    */

}