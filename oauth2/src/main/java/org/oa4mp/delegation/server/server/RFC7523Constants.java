package org.oa4mp.delegation.server.server;


import static org.oa4mp.delegation.server.server.RFC8693Constants.IETF_CAPUT;

/**
 * Constants relating to <a href = "https://datatracker.ietf.org/doc/html/rfc7523">RFC7523</a>,
 * client authorization with JWTs.
 * <p>Created by Jeff Gaynor<br>
 * on 6/1/23 at  1:49 PM
 */
public interface RFC7523Constants {
    // addresses https://github.com/ncsa/oa4mp/issues/101
    String CLIENT_ASSERTION_TYPE = "client_assertion_type";
    String CLIENT_ASSERTION = "client_assertion";
    String ASSERTION_JWT_BEARER = IETF_CAPUT + "oauth:client-assertion-type:jwt-bearer";
    String GRANT_TYPE_JWT_BEARER = IETF_CAPUT + "oauth:grant-type:jwt-bearer";
    String ASSERTION = "assertion";
    long  DEFAULT_LIFETIME = 1000*15*60L; // 15 minutes

    // For admin clients that initiate flows.
    String ADMIN_CLIENT = "admin_client";
    String ADMIN_KID = "admin_kid";
}
