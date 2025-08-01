package org.oa4mp.server.api;

import edu.uiuc.ncsa.security.core.Identifier;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.common.token.AuthorizationGrant;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 17, 2011 at  3:26:21 PM
 */
public class OA4MPServiceTransaction extends ServiceTransaction {
    static final long serialVersionUID = 0xcafed00d2L;


    public boolean isConsentPageOK() {
        return consentPageOK;
    }

    public void setConsentPageOK(boolean consentPageOK) {
        this.consentPageOK = consentPageOK;
    }

    boolean consentPageOK = false;
    public OA4MPServiceTransaction(Identifier identifier) {
        super(identifier);
    }

    public OA4MPServiceTransaction(AuthorizationGrant ag) {
        super(ag);
    }

    String myproxyUsername;

    public String getMyproxyUsername() {
        return myproxyUsername;
    }

    public void setMyproxyUsername(String myproxyUsername) {
        this.myproxyUsername = myproxyUsername;
    }

    @Override
    protected String formatToString() {
        return super.formatToString() + ",myproxy username=" + getMyproxyUsername();
    }

    @Override
    public boolean equals(Object obj) {
        if (!super.equals(obj)) return false;
        OA4MPServiceTransaction st = (OA4MPServiceTransaction) obj;
        if (!checkEquals(getMyproxyUsername(), st.getMyproxyUsername())) return false;
        if (!checkEquals(getUsername(), st.getUsername())) return false;
        if(st.getClient() == null && getClient() == null) return true;
        if(st.getClient() == null){
            if(getClient() == null){
                return true;
            }
            return false;
        }else{
            if(getClient() ==null){
                return false;
            }
            return st.getClient().getIdentifier().equals(getClient().getIdentifier());
        }
    }
}
