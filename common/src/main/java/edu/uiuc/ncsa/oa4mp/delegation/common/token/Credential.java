package edu.uiuc.ncsa.oa4mp.delegation.common.token;


import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Models a credential, which consists of a private key and X509 certificate.
 * <p>Created by Jeff Gaynor<br>
 * on Apr 4, 2011 at  3:20:17 PM
 */
public interface Credential extends ProtectedAsset {
    PrivateKey getPrivateKey();

    void setPrivateKey(PrivateKey privateKey);

    X509Certificate getX509Certificate();

    void setX509Certificate(X509Certificate x509Certificate);
}
