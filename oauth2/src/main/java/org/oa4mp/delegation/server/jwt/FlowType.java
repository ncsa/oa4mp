package org.oa4mp.delegation.server.jwt;

import edu.uiuc.ncsa.security.util.functor.FunctorType;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/15/20 at  8:27 AM
 */
public enum FlowType implements FunctorType {
    /**
     * Allows for issuing access tokens
     */
    ACCESS_TOKEN("access_token"),
    /**
     * Allows for issuing id tokens
     */
    ID_TOKEN("id_token"),
    REFRESH_TOKEN("refresh_token"),
    USER_INFO("user_info"),
    GET_CERT("get_cert"),
    GET_CLAIMS("get_claims"),
    AT_DO_TEMPLATES("at_do_templates"),
    /**
     * Allows for accepting requests. If this is set to false, then any attempt to access the
     * system generates an exception. It effectively is the same as setting all other state
     * variables to false.
     */
    ACCEPT_REQUESTS("accept_requests");

    FlowType(String value) {
        this.value = value;
    }

    String value;

    @Override
    public String getValue() {
        return value;
    }
}


