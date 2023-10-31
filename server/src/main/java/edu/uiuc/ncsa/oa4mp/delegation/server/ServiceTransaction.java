package edu.uiuc.ncsa.oa4mp.delegation.server;


import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions.BasicTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.util.crypto.MyPKCS10CertRequest;
import edu.uiuc.ncsa.security.util.pkcs.MyCertUtil;

import java.net.URI;
import java.util.List;

/**
 * Server-side transactions. These should be stored between (the stateless) calls in the protocol.
 * <p>Created by Jeff Gaynor<br>
 * on Apr 16, 2010 at  10:36:51 AM
 */
public class ServiceTransaction extends BasicTransaction {
    public ServiceTransaction(Identifier identifier) {
        super(identifier);
    }

    public ServiceTransaction(AuthorizationGrant ag) {
        super(ag);
    }

    public boolean authGrantValid;
    public boolean accessTokenValid;

    public boolean isAuthGrantValid() {
        return authGrantValid;
    }

    public void setAuthGrantValid(boolean authGrantValid) {
        this.authGrantValid = authGrantValid;
    }


    public boolean isAccessTokenValid() {
        return accessTokenValid;
    }

    public void setAccessTokenValid(boolean accessTokenValid) {
        this.accessTokenValid = accessTokenValid;
    }

    public URI getCallback() {
        return callback;
    }

    public void setCallback(URI callback) {
        this.callback = callback;
    }

    URI callback;


    public Client getClient() {
        return client;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    Client client;
    long lifetime = 0;

    public void setLifetime(long lifetime) {
        this.lifetime = lifetime;
    }

    /**
     * The lifetime of the certificate. This is stored internally in milliseconds, so must be
     * converted to seconds before use in most applications.
     *
     * @return
     */
    public long getLifetime() {
        return lifetime;
    }



    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    String username;

    public MyPKCS10CertRequest getCertReq() {
        if (certReq != null) {
            return certReq;
        }
        if (certReqString == null) {
            return null;
        }
        // Need to do it this way since cert requests are not actually serializable
        return MyCertUtil.fromStringToCertReq(getCertReqString());
    }

    public void setCertReqString(String certReqString) {
        if (certReqString == null && certReq != null) {
            certReqString = MyCertUtil.fromCertReqToString(certReq);
        }
        this.certReqString = certReqString;
    }

    public String getCertReqString() {
        return certReqString;
    }

    String certReqString;

    public void setCertReq(String certReq) {
        certReqString = certReq;
    }

    public void setCertReq(MyPKCS10CertRequest certReq) {
        this.certReq = certReq;
        certReqString = MyCertUtil.fromCertReqToString(certReq);
    }

    transient MyPKCS10CertRequest certReq;
    protected String formatToString(){
        String out = "id=" + getIdentifierString() + ", authGrant=" + getAuthorizationGrant() + "(" + (isAuthGrantValid() ? "" : "in") + "valid)";
        out = out + ", verifier=" + (!hasVerifier() ? "(none)" : getVerifier());
        out = out + ", access token=" + getAccessToken() + "(" + (isAccessTokenValid() ? "" : "in") + "valid)";
        out = out + ", lifetime=" + getLifetime();
              return out;
    }
    public String toString() {
        return  getClass().getSimpleName() + "[" + formatToString() + "]";
    }

    @Override
    public boolean equals(Object obj) {
        if (!super.equals(obj)) {
            return false;
        }
        if (!(obj instanceof ServiceTransaction)) {
            return false;
        }
        ServiceTransaction st = (ServiceTransaction) obj;
        if (isAuthGrantValid() != st.isAuthGrantValid()) return false;
        if (isAccessTokenValid() != st.isAccessTokenValid()) return false;
        if (getLifetime() != st.getLifetime()) return false;

        return true;
    }

   public List<String> getResponseTypes(){
      return null;
   }
}
