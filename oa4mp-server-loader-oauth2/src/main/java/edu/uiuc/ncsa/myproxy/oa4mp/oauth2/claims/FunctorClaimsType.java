package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.util.functor.FunctorType;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/6/18 at  9:17 AM
 */
public enum FunctorClaimsType implements FunctorType {
    SET("$set"),
    INCLUDE("$include"),
    EXCLUDE("$exclude"),
    REMOVE("$remove"),
    IS_MEMBER_OF("$isiMemberOf");

    FunctorClaimsType(String value) {
        this.value = value;
    }

    String value;

    @Override
    public String getValue() {
        return value;
    }
}
