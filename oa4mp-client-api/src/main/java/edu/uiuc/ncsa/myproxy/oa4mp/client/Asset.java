package edu.uiuc.ncsa.myproxy.oa4mp.client;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.util.crypto.CertUtil;
import edu.uiuc.ncsa.security.util.crypto.KeyUtil;
import edu.uiuc.ncsa.security.util.crypto.MyPKCS10CertRequest;
import net.sf.json.JSONObject;

import java.net.URI;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
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
     *
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

    protected String USERNAME_KEY = "username";
    protected String PRIVATE_KEY_KEY = "private_key";
    protected String X509_CERTS_KEY = "x509_certs";
    protected String CREATE_TIME_KEY = "create_time";
    protected String CERT_REQUEST_KEY = "cert_request";
    protected String REDIRECT_URI_KEY = "redirect_uri";
    protected String ASSET_ID_KEY = "asset_id";
    protected String TOKEN_KEY = "auth_grant";


    public JSONObject toJSON() {
        JSONObject jsonObject = new JSONObject();
        if (StringUtils.isTrivial(getUsername())) {
            jsonObject.put(USERNAME_KEY, getUsername());
        }
        if (getPrivateKey() != null) {
            jsonObject.put(PRIVATE_KEY_KEY, KeyUtil.toPKCS8PEM(getPrivateKey()));
        }
        if (getCertificates() != null && 0 < getCertificates().length) {
            jsonObject.put(X509_CERTS_KEY, CertUtil.toPEM(getCertificates()));
        }
        jsonObject.put(CREATE_TIME_KEY, Iso8601.date2String(getCreationTime()));
        if (getCertReq() != null) {
            jsonObject.put(CERT_REQUEST_KEY, CertUtil.fromCertReqToString(getCertReq()));
        }
        if (getRedirect() != null) {
            jsonObject.put(REDIRECT_URI_KEY, getRedirect().toString());
        }
        if (getIdentifier() != null) {
            jsonObject.put(ASSET_ID_KEY, getIdentifierString());
        }
        if (getToken() != null) {
            jsonObject.put(TOKEN_KEY, getToken().toString());
        }
        return jsonObject;
    }

    public void fromJSON(JSONObject jsonObject) {
        if (jsonObject.containsKey(ASSET_ID_KEY)) {
            setIdentifier(BasicIdentifier.newID(jsonObject.getString(ASSET_ID_KEY)));
        }
        if (jsonObject.containsKey(TOKEN_KEY)) {
            setToken(BasicIdentifier.newID(jsonObject.getString(TOKEN_KEY)));
        }
        if (jsonObject.containsKey(REDIRECT_URI_KEY)) {
            setRedirect(URI.create(jsonObject.getString(REDIRECT_URI_KEY)));
        }
        if (jsonObject.containsKey(USERNAME_KEY)) {
            setUsername(jsonObject.getString(USERNAME_KEY));
        }
        if (jsonObject.containsKey(CREATE_TIME_KEY)) {
            try {
                setCreationTime(Iso8601.string2Date(jsonObject.getString(CREATE_TIME_KEY)).getTime());
            } catch (ParseException e) {
                e.printStackTrace();
            }
        }
        if (jsonObject.containsKey(X509_CERTS_KEY)) {
            try {
                setCertificates(CertUtil.fromX509PEM(jsonObject.getString(X509_CERTS_KEY)));
            } catch (CertificateException e) {
                e.printStackTrace();
            }
        }
        if (jsonObject.containsKey(CERT_REQUEST_KEY)) {
            setCertReq(CertUtil.fromStringToCertReq(jsonObject.getString(CERT_REQUEST_KEY)));
        }
    }
}
