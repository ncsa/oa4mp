package org.oa4mp.delegation.server.server;

/**
 * Constants for <a href="https://datatracker.ietf.org/doc/html/rfc7662">RFC 7662</a>,
 * the token introspection endpoint.
 * <h2>Note</h2>
 * These are also used in <a href="https://datatracker.ietf.org/doc/html/rfc7009">RFC 7009</a>,
 * for token revocation.
 * <p>Created by Jeff Gaynor<br>
 * on 5/19/21 at  7:18 AM
 */
public interface RFC7662Constants {
    String TOKEN = "token";
    String TOKEN_TYPE_HINT = "token_type_hint";
    String TYPE_ACCESS_TOKEN = "access_token";
    String TYPE_REFRESH_TOKEN = "refresh_token";

    String ACTIVE = "active";
    String TOKEN_TYPE = "token_type";
    String USERNAME = "username";
}
