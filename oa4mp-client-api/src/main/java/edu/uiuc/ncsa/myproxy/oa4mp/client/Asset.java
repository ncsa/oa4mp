package edu.uiuc.ncsa.myproxy.oa4mp.client;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;

import java.net.URI;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * A storage class that contains the
 * <ul>
 * <li>certificate chain</li>
 * <li>private key used in the request</li>
 * <li>the redirect returned from the server</li>
 * <li>the username used for the MyProxy call</li>
 * <li>the creation time of this entry (useful for removing expired/old assets)</li>
 * </ul>
 * read more on the use of this in the {@link edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore}
 * javadoc.
 * <p>Created by Jeff Gaynor<br>
 * on 1/29/13 at  10:51 AM
 */
public class Asset extends IdentifiableImpl {
    public Asset(Identifier identifier) {
        super(identifier);
    }

    String username;
    X509Certificate[] certificates;
    PrivateKey privateKey;
    URI redirect;
    Date creationTime = new Date(); // set it to now
    MyPKCS10CertRequest certReq;
    Identifier token;

    /**
     * The token is the identifier returned from the server. This should be stored for future reference.
     * @return
     */
    public Identifier getToken() {
        return token;
    }

    public void setToken(Identifier token) {
        this.token = token;
    }

    public MyPKCS10CertRequest getCertReq() {
        return certReq;
    }

    public void setCertReq(MyPKCS10CertRequest certReq) {
        this.certReq = certReq;
    }


    public Date getCreationTime() {
        return creationTime;
    }

    public void setCreationTime(Date creationTime) {
        this.creationTime = creationTime;
    }

    public URI getRedirect() {
        return redirect;
    }

    public void setRedirect(URI redirect) {
        this.redirect = redirect;
    }

    public X509Certificate[] getCertificates() {
        return certificates;
    }

    public void setCertificates(X509Certificate[] certificates) {
        this.certificates = certificates;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String toString() {
        String out = "Asset[";
        out = out + "id=" + getIdentifierString() + ", uri=" + redirect;
        out = out + "]";
        return out;
    }
}
