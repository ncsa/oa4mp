package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.functor.claims;

import edu.uiuc.ncsa.security.util.functor.FunctorType;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/6/18 at  9:17 AM
 */
public enum FunctorClaimsType implements FunctorType {
    SET("$set"),
    GET("$get"),
    INCLUDE("$include"),
    EXCLUDE("$exclude"),
    REMOVE("$remove"),
    HAS_CLAIM("$hasClaim"),
    IS_MEMBER_OF("$isMemberOf"),
    RENAME("$rename"),
    HAS_SCOPE("$hasScope");

    FunctorClaimsType(String value) {
        this.value = value;
    }

    String value;

    @Override
    public String getValue() {
        return value;
    }
}
