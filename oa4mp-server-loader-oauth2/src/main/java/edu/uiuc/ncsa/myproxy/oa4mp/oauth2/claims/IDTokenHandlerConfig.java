package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;

import javax.servlet.http.HttpServletRequest;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/30/20 at  11:12 AM
 */
public class IDTokenHandlerConfig extends AbstractPayloadHandlerConfig {
    public IDTokenHandlerConfig(IDTokenClientConfig idTokenClientConfig, OA2SE oa2se, OA2ServiceTransaction transaction, HttpServletRequest request) {
        super(idTokenClientConfig, oa2se, transaction, request);
    }

}
