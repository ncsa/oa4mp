package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/26/20 at  4:57 PM
 */
public class WLCGTokenHandler extends AbstractPayloadHandler {
    public WLCGTokenHandler(OA2SE oa2se, OA2ServiceTransaction transaction, HttpServletRequest request) {
        super(oa2se, transaction, request);
    }

    public WLCGTokenHandler(OA2SE oa2se, OA2ServiceTransaction transaction) {
        super(oa2se, transaction);
    }

    @Override
    public void init() throws Throwable {

    }

    @Override
    public void addRequestState(ScriptRunRequest req) throws Throwable {

    }

    @Override
    public void handleResponse(ScriptRunResponse resp) throws Throwable {

    }

    @Override
    public void checkClaims() throws Throwable {

    }

    @Override
    public List<ClaimSource> getSources() throws Throwable {
        return null;
    }

    @Override
    public void finish() throws Throwable {

    }

    @Override
    public void saveState() throws Throwable {

    }

    @Override
    public void setAccountingInformation() {

    }

    @Override
    public void refreshAccountingInformation() {

    }
}
