package org.oa4mp.server.loader.qdl.claims;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.claims.*;
import org.oa4mp.server.loader.qdl.scripting.OA2State;
import org.oa4mp.delegation.server.server.claims.ClaimSource;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/20 at  11:30 AM
 */
public class ConfigtoCS implements CSConstants {


    public  ClaimSource convert(QDLStem arg, OA2SE oa2SE) {
        return convert(arg, null, oa2SE);
    }

    public  ClaimSource convert(QDLStem arg, State qdlState, OA2SE oa2SE) {
        switch (arg.getString(CS_DEFAULT_TYPE)) {
            case CS_TYPE_BASIC:
                return new BasicClaimsSourceImpl(arg);
            case CS_TYPE_CODE:
                return new CodeClaimSource(arg);
            case CS_TYPE_FILE:
                return new FSClaimSource(arg);
            case CS_TYPE_LDAP:
                return new LDAPClaimsSource(arg, oa2SE);
            case CS_TYPE_FILTER_HEADERS:
                return new HTTPHeaderClaimsSource(arg);
            case CS_TYPE_ALL_HEADERS:
                QDLHeadersClaimsSource cs = new QDLHeadersClaimsSource(arg);
                if(qdlState instanceof OA2State) {
                    cs.setOa2State((OA2State)qdlState);
                }
                return cs;
            case CS_TYPE_NCSA:
                return new NCSALDAPClaimSource(arg, oa2SE);
        }
        throw new IllegalArgumentException("Error: Unrecognized claim source type \"" + arg.getString(CS_DEFAULT_TYPE) + "\"");
    }

}
