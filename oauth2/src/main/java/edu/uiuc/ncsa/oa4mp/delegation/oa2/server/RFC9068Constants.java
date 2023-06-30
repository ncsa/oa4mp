package edu.uiuc.ncsa.oa4mp.delegation.oa2.server;

import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/16/21 at  8:24 AM
 */
public interface RFC9068Constants {
    String HEADER_TYPE = "at+jwt";
    String RFC9068_TAG = "rfc9068";
    String RFC9068_TAG2 = "rfc_9068";
    String TYPE_NAME = "type";
    String AUTHENTICATION_CLASS_REFERENCE = OA2Claims.AUTHENTICATION_CLASS_REFERENCE;
    String AUTHENTICATION_METHOD_REFERENCE = OA2Claims.AUTHENTICATION_METHOD_REFERENCE;
    String AUTHENTICATION_TIME = "auth_time";
}
