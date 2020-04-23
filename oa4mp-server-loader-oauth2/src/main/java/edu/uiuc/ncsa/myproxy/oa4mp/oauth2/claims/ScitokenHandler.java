package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/21/20 at  4:55 PM
 */
public class ScitokenHandler extends AbstractPayloadHandler {
    String ST_SCOPE = "scope";
    String ST_CLIENT_IDENTIFIER = "cid";
    String CLAIM_OPERATION_WRITE = "write";
    String CLAIM_OPERATION_READ = "read";
    String CLAIM_OPERATION_QUEUE = "queue";
    String CLAIM_OPERATION_EXECUTE = "execute";
    String VERSION_2_0 = "2.0";

    public ScitokenHandler(OA2SE oa2se, OA2ServiceTransaction transaction, HttpServletRequest request) {
        super(oa2se, transaction, request);
    }

    public ScitokenHandler(OA2SE oa2se, OA2ServiceTransaction transaction) {
        super(oa2se, transaction);
    }

    protected String getVersion() {
        return VERSION_2_0;
    }

    @Override
    public void init() throws Throwable {
        JSONObject sciTokens = getClaims();
  //      sciTokens.put(ISSUER, parameters.get(ISSUER));
        // subject is optional, so for now we won't return one.
    //    sciTokens.put(SUBJECT, parameters.get(SUBJECT));
        sciTokens.put(EXPIRATION, System.currentTimeMillis() / 1000L + 900L);
      //  sciTokens.put(AUDIENCE, stClient.getIdentifierString());
        sciTokens.put(ISSUED_AT, System.currentTimeMillis() / 1000L);
        sciTokens.put(NOT_VALID_BEFORE, (System.currentTimeMillis() - 5000L) / 1000L); // not before is 5 minutes before current
        DebugUtil.trace(this, "version = " + getVersion());
        sciTokens.put(ST_CLIENT_IDENTIFIER, transaction.getOA2Client().getIdentifierString());

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
    public JSONObject execute(ClaimSource source, JSONObject claims) throws Throwable {
        return null;
    }

    @Override
    public void finish() throws Throwable {

    }

    @Override
    public void saveState() throws Throwable {

    }

    @Override
    public JSONObject getClaims() {
        return null;
    }

    @Override
    public JSONObject getExtendedAttributes() {
        return null;
    }

    @Override
    public void setAccountingInformation() {

    }
}
