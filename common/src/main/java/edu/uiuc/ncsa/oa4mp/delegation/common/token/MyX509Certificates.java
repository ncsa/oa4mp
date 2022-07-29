package edu.uiuc.ncsa.oa4mp.delegation.common.token;

import edu.uiuc.ncsa.security.util.pkcs.MyCertUtil;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * This wraps whatever X509 certificate is returned (this depends on the implementation).
 * <p>Created by Jeff Gaynor<br>
 * on May 3, 2011 at  12:31:17 PM
 */
public class MyX509Certificates implements ProtectedAsset {

    public MyX509Certificates(Collection<X509Certificate> certs) {
        this.x509Certificates = certs.toArray(new X509Certificate[certs.size()]);
    }
    public MyX509Certificates(X509Certificate [] x509Certificates) {
        this.x509Certificates = x509Certificates;
    }

    public X509Certificate [] getX509Certificates() {
        return x509Certificates;
    }

    public String getX509CertificatesPEM()
            throws CertificateEncodingException {
        String pem = "";
        for (int i = 0; i < x509Certificates.length; ++i){
            pem += MyCertUtil.toPEM(x509Certificates[i]) + "\n";
        }
        return pem;
    }

    public void setX509Certificates(X509Certificate [] x509Certificates) {
        this.x509Certificates = x509Certificates;
    }

    public X509Certificate[] x509Certificates;

    @Override
    public String toString() {
        String str = "MyX509Certificates[";
        for (int i = 0; i < x509Certificates.length; ++i) {
            str += "cert = " + (x509Certificates[i] == null ? "(null)" : x509Certificates[i]);
        }
        str += "]";
        return str;
    }
}