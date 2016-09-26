package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 17, 2011 at  3:26:21 PM
 */
public class OA4MPServiceTransaction extends ServiceTransaction {
    static final long serialVersionUID = 0xcafed00d2L;

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
        return true;
    }
}
