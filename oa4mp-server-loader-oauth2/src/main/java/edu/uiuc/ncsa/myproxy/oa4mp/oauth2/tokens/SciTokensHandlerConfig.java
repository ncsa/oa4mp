package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadHandlerConfig;

import javax.servlet.http.HttpServletRequest;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/30/20 at  11:03 AM
 */
public class SciTokensHandlerConfig extends AbstractPayloadHandlerConfig {
    public SciTokensHandlerConfig(SciTokenClientConfig sciTokenConfig,
                                  OA2SE oa2se,
                                  OA2ServiceTransaction transaction,
                                  HttpServletRequest request) {
        super(sciTokenConfig, oa2se, transaction, request);
    }

    public SciTokenClientConfig getSciTokenConfig() {
        return (SciTokenClientConfig)getClientConfig();
    }

}
