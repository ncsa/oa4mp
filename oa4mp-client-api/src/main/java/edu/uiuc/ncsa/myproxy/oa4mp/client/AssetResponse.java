package edu.uiuc.ncsa.myproxy.oa4mp.client;

import edu.uiuc.ncsa.security.delegation.services.Response;

import java.security.cert.X509Certificate;

/**
 * Response from a server containing the certificate chain and user name.
 * <p>Created by Jeff Gaynor<br>
 * on 7/1/11 at  3:28 PM
 */
public class AssetResponse  implements Response{

    X509Certificate x509Certificates[];
    String username;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public X509Certificate[] getX509Certificates() {
        return x509Certificates;
    }

    public void setX509Certificates(X509Certificate[] x509Certificates) {
        this.x509Certificates = x509Certificates;
    }
}
