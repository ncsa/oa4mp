package org.scitokens.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ATServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.IssuerTransactionState;
import net.sf.json.JSONArray;
import org.scitokens.util.STConstants;
import org.scitokens.util.STTransaction;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.server.ATIResponse2;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.Map;

import static edu.uiuc.ncsa.security.oauth_2_0.server.OA2Claims.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  1:10 PM
 */
public class STATServlet extends OA2ATServlet {
    @Override
    protected IssuerTransactionState doAT(HttpServletRequest request, HttpServletResponse response, OA2Client client) throws Throwable {
        IssuerTransactionState state = super.doAT(request, response, client);
        ATIResponse2 atResponse = (ATIResponse2) state.getIssuerResponse();
        // reset token to SciToken here.
        JSONObject sciTokens = new JSONObject();
        sciTokens.put(STConstants.JWT_ID, atResponse.getAccessToken().getToken());

        Map<String, String> parameters = atResponse.getParameters();
        STTransaction stTransaction = (STTransaction)state.getTransaction();

        sciTokens.put(ISSUER, parameters.get(ISSUER));
        sciTokens.put(SUBJECT, parameters.get(SUBJECT));
        sciTokens.put(EXPIRATION, Long.valueOf(System.currentTimeMillis() / 1000L + 900L));
      //  sciTokens.put(AUDIENCE, parameters.get("client_id"));
        sciTokens.put(ISSUED_AT, Long.valueOf(System.currentTimeMillis() / 1000L));
        JSONArray array = new JSONArray();
        array.add("read");
        array.add("write");
        sciTokens.put("authz", array);
        sciTokens.put("path","/user/dweitzel");
        if(isEmpty(stTransaction.getStScopes())){
            sciTokens.put(STConstants.SCOPE,"default");
        }else {
            sciTokens.put(STConstants.SCOPE, stTransaction.getStScopes());
        }
        DebugUtil.dbg(this,"scitoken=" + sciTokens.toString(2));
        String newAT = JWTUtil.createJWT(sciTokens, ((OA2SE) getServiceEnvironment()).getJsonWebKeys().getDefault());
        AccessTokenImpl ati = new AccessTokenImpl(URI.create(newAT), null);
        atResponse.setAccessToken(ati);
        return state;
    }
}
