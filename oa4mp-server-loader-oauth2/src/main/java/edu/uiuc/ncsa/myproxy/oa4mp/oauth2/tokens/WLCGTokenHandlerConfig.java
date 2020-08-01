package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractClientConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadHandlerConfig;

import javax.servlet.http.HttpServletRequest;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/22/20 at  2:27 PM
 */
public class WLCGTokenHandlerConfig extends AbstractPayloadHandlerConfig {
    public WLCGTokenHandlerConfig(AbstractClientConfig abstractClientConfig, OA2SE oa2se, OA2ServiceTransaction transaction, HttpServletRequest request) {
        super(abstractClientConfig, oa2se, transaction, request);
    }
}
