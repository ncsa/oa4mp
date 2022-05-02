package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.PayloadHandlerConfig;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;

import javax.servlet.http.HttpServletRequest;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/30/22 at  5:55 AM
 */
public class ServerQDLScriptHandlerConfig implements PayloadHandlerConfig {

    public ServerQDLScriptHandlerConfig( OA2SE oa2se,
                                        OA2ServiceTransaction transaction,
                                        TXRecord txRecord,
                                        HttpServletRequest request) {
        this.oa2SE = oa2se;
        this.transaction = transaction;
        this.txRecord = txRecord;
        this.request = request;

    }

    OA2SE oa2SE;
    OA2ServiceTransaction transaction;
    TXRecord txRecord;
    HttpServletRequest request;

    @Override
    public ScriptSet getScriptSet() {
        return oa2SE.getQDLEnvironment().getServerScripts();
    }

    @Override
    public boolean isLegacyHandler() {
        return false;
    }

    @Override
    public void setLegacyHandler(boolean b) {
        if(b){throw new NotImplementedException("Cannot set handler legacy");}
    }
}
