package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.*;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.ClaimSource;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.QDLStem;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/20 at  11:30 AM
 */
public class ConfigtoCS implements CSConstants {

/*    public static QDLStem convert(ClaimSource source) {
        if (source instanceof FSClaimSource) {
            return ClaimSourceConfigConverter.convert(source, CSConstants.CS_TYPE_FILE);
        }
        if (source instanceof HTTPHeaderClaimsSource) {
            return ClaimSourceConfigConverter.convert(source, CSConstants.CS_TYPE_HEADERS);
        }
        if (source instanceof NCSALDAPClaimSource) {
            return ClaimSourceConfigConverter.convert(source, CSConstants.CS_TYPE_NCSA);
        }

        if (source instanceof LDAPClaimsSource) {
            return ClaimSourceConfigConverter.convert(source, CSConstants.CS_TYPE_LDAP);
        }

        if (source instanceof BasicClaimsSourceImpl) {
            throw new GeneralException("Error: This probably means you instantiated a class using the code type, but handling it has not been implement yet.");
        }

        throw new IllegalArgumentException("Error: Unknown claims source type");
    }*/

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
