package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.*;
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
            case CS_TYPE_HEADERS:
                return new HTTPHeaderClaimsSource(arg);
            case CS_TYPE_NCSA:
                return new NCSALDAPClaimSource(arg, oa2SE);
        }
        throw new IllegalArgumentException("Error: Unrecognized claim source type \"" + arg.getString(CS_DEFAULT_TYPE) + "\"");
    }

    /*
      public static ClaimSource convert(QDLStem arg, State qdlState, OA2SE oa2SE) {
        switch (arg.getString(CS_DEFAULT_TYPE)) {
            case CS_TYPE_CODE:
                return doCode(arg);
            case CS_TYPE_FILE:
                ClaimSourceConfiguration cfg = ClaimSourceConfigConverter.convert(arg);
                return new FSClaimSource(cfg);
            case CS_TYPE_LDAP:
                LDAPConfiguration ldapCfg = (LDAPConfiguration) ClaimSourceConfigConverter.convert(arg);
                LDAPClaimsSource ldapClaimsSource;
                if (oa2SE == null) {
                    ldapClaimsSource = new LDAPClaimsSource();
                } else {
                    ldapClaimsSource = new LDAPClaimsSource(oa2SE);
                }
                ldapClaimsSource.setConfiguration(ldapCfg);
                return ldapClaimsSource;
            case CS_TYPE_HEADERS:
                ClaimSourceConfiguration hcfg = ClaimSourceConfigConverter.convert(arg);

                HTTPHeaderClaimsSource httpHeaderClaimsSource = new HTTPHeaderClaimsSource();
                httpHeaderClaimsSource.setConfiguration(hcfg);
                return httpHeaderClaimsSource;
            case CS_TYPE_NCSA:
                String searchName;
                if (arg.containsKey(CS_LDAP_SEARCH_NAME)) {
                    searchName = arg.getString(CS_LDAP_SEARCH_NAME);
                } else {
                    searchName = NCSALDAPClaimSource.DEFAULT_SEACH_NAME;
                }
                NCSALDAPClaimSource ncsaldapClaimSource;
                if (oa2SE == null) {
                    ncsaldapClaimSource = new NCSALDAPClaimSource();
                } else {
                    ncsaldapClaimSource = new NCSALDAPClaimSource(oa2SE);
                }
                return ncsaldapClaimSource;

        }
        throw new IllegalArgumentException("Error: Unrecognized claim source type \"" + arg.getString(CS_DEFAULT_TYPE) + "\"");
    }
     */
/*    private static ClaimSource doCode(QDLStem arg) {
        BasicClaimsSourceImpl claimsSource = null;
        ClaimSourceConfiguration cfg = ClaimSourceConfigConverter.convert(arg);

        try {
            Class<?> c = Class.forName(arg.getString(CS_CODE_JAVA_CLASS));
            Object object = c.newInstance();
            if (!(object instanceof BasicClaimsSourceImpl)) {
                throw new IllegalArgumentException("Error: Object must extend BasicClaimSourceImpl");
            }
            claimsSource = (BasicClaimsSourceImpl) object;
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InstantiationException e) {
            e.printStackTrace();
        }
        claimsSource.setConfiguration(cfg);
        return claimsSource;
    }*/
}
