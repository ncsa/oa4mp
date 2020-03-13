package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.FSClaimSource;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.HTTPHeaderClaimsSource;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.LDAPClaimsSource;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.NCSALDAPClaimSource;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/20 at  11:30 AM
 */
public class ConfigtoCS implements CSConstants {
    public static StemVariable convert(ClaimSource source) {
        if(source instanceof FSClaimSource){
            return ClaimSourceConfigConverter.convert(source, CSConstants.CS_TYPE_FILE);
        }
        if(source instanceof HTTPHeaderClaimsSource){
            return ClaimSourceConfigConverter.convert(source, CSConstants.CS_TYPE_HEADERS);
        }
        if(source instanceof NCSALDAPClaimSource){
            return ClaimSourceConfigConverter.convert(source, CSConstants.CS_TYPE_NCSA);
        }

        if(source instanceof LDAPClaimsSource){
            return ClaimSourceConfigConverter.convert(source, CSConstants.CS_TYPE_LDAP);
        }

        throw new IllegalArgumentException("Error: Unknown claims source type");
    }
    public static ClaimSource convert(StemVariable arg) {
        switch (arg.getString(CS_DEFAULT_TYPE)) {
            case CS_TYPE_FILE:
                ClaimSourceConfiguration cfg = ClaimSourceConfigConverter.convert(arg);
                return new FSClaimSource(cfg);
            case CS_TYPE_LDAP:
                LDAPConfiguration ldapCfg = (LDAPConfiguration) ClaimSourceConfigConverter.convert(arg);
                LDAPClaimsSource ldapClaimsSource = new LDAPClaimsSource();
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
                return new NCSALDAPClaimSource(NCSALDAPClaimSource.DEFAULT_SEACH_NAME);

        }
        throw new IllegalArgumentException("Error: Unrecognized claim source type \"" + arg.getString(CS_DEFAULT_TYPE) + "\"");
    }
}
