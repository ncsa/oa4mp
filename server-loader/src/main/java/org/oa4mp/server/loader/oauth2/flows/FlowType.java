package org.oa4mp.server.loader.oauth2.flows;


/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/23/18 at  11:36 AM
 */
public enum FlowType  {
    /**
     * Allows for issuing access tokens
     */
    ACCESS_TOKEN("$access_token"),
    /**
     * Allows for issuing id tokens
     */
    ID_TOKEN("$id_token"),
    REFRESH_TOKEN("$refresh_token"),
    USER_INFO("$user_info"),
    GET_CERT("$get_cert"),
    GET_CLAIMS("$get_claims"),
    /**
     * This sets the claim source.
     */
    SET_CLAIM_SOURCE("$set_claim_source"),
    /**
     * Allows for accepting requests. If this is set to false, then any attempt to access the
     * system generates an exception. It effectively is the same as setting all other state
     * variables to false.
     */
    ACCEPT_REQUESTS("$accept_requests"),
    AT_DO_TEMPLATES("$at_do_templates");

    FlowType(String value) {
        this.value = value;
    }

    String value;

    public String getValue() {
        return value;
    }
}


