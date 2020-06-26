package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.PayloadHandler;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/21/20 at  5:00 PM
 */
public abstract class AbstractPayloadHandler implements PayloadHandler {
    protected OA2ServiceTransaction transaction;
    protected OA2SE oa2se;
    protected JSONObject claims;
    protected HttpServletRequest request;

    /**
     * Create the instance for the authorization phase, while there is an {@link HttpServletRequest} with possible
     * headers that need to be processed.
     *
     * @param oa2se
     * @param transaction
     * @param request
     */

    public AbstractPayloadHandler(OA2SE oa2se, OA2ServiceTransaction transaction, HttpServletRequest request) {
        this(oa2se, transaction);
        this.request = request;
        claims = new JSONObject();
    }

    /**
     * For creating an instance after the authorization phase.
     *
     * @param oa2se
     * @param transaction
     */

    public AbstractPayloadHandler(OA2SE oa2se, OA2ServiceTransaction transaction) {
        this.oa2se = oa2se;
        this.transaction = transaction;
    }


    @Override
    public JSONObject getClaims() {
        if (claims == null) {
            claims = transaction.getClaims();
        }
        return claims;
    }

    JSONObject extendedAttributes = null;

    /**
     * Gets the extended attributes from the current transaction. See {@link OA2ServiceTransaction#getExtendedAttributes()}
     * for more.
     * @return
     */
    public JSONObject getExtendedAttributes() {
        if (extendedAttributes == null) {
            extendedAttributes = transaction.getExtendedAttributes();
        }
        return extendedAttributes;
    }

    protected boolean isEmpty(String x) {
        return x == null || 0 == x.length();
    }

    @Override
    public JSONObject execute(ClaimSource source, JSONObject claims) throws Throwable {
        if (transaction.getOA2Client().isPublicClient()) {
            // Public clients do not get more than basic claims.
            return claims;
        }
        // Fix for CIL-693:
        // Inject current state here!
         if(source instanceof BasicClaimsSourceImpl){
             ((BasicClaimsSourceImpl)source).setOa2SE(oa2se);
         }
        return source.process(claims, transaction);
    }
    @Override
    public void refresh() throws Throwable {

    }

}
