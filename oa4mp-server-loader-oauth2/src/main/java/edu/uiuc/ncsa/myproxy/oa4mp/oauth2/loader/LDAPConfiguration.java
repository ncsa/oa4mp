package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.LDAPConfigurationUtil.AttributeEntry;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;

import javax.naming.Name;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapContext;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/3/16 at  11:17 AM
 */
public class LDAPConfiguration {
    String server;
    Integer port = null;
    SSLConfiguration sslConfiguration;


    public String getSecurityPrincipal() {
        return securityPrincipal;
    }

    public void setSecurityPrincipal(String securityPrincipal) {
        this.securityPrincipal = securityPrincipal;
    }

    String securityPrincipal;

    public String getSearchBase() {
        return searchBase;
    }

    public void setSearchBase(String searchBase) {
        this.searchBase = searchBase;
    }

    String searchBase;

    Map<String,AttributeEntry> searchAttributes = new HashMap<>();

    /**
     * Search attributes are recorded as a map. The key  is the search term in the LDAP query. The value
     * is the name that should be returned for this attribute in the claim.
     * @return
     */
    public Map<String,AttributeEntry> getSearchAttributes() {
        return searchAttributes;
    }

    public void setSearchAttributes(Map<String,AttributeEntry> searchAttributes) {
        this.searchAttributes = searchAttributes;
    }

    /**
     * If this is disabled (or there is no configuration for one) then the LDAP scope handler should
     * not be created, just a basic one.
     * @return
     */
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    boolean enabled = false;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    String password;

    public Integer getPort() {
        return port;
    }

    public void setPort(Integer port) {
        this.port = port;
    }

    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public SSLConfiguration getSslConfiguration() {
        return sslConfiguration;
    }

    public void setSslConfiguration(SSLConfiguration sslConfiguration) {
        this.sslConfiguration = sslConfiguration;
    }

    /**
     * This will return the corresponding number for the security authorization (see constants in {@link LDAPConfigurationUtil})
     * which can be used for switch statements.
     * @return
     */
    public int getAuthType() {
        return authType;
    }

    public void setAuthType(int authType) {
        this.authType = authType;
    }

    int authType = LDAPConfigurationUtil.LDAP_AUTH_UNSPECIFIED_KEY;
    String contextName;

    /**
     * The name of the context for the JNDI {@link LdapContext#search(Name, Attributes)} function. If this is omitted
     * in the configuration, then it is set to the empty string.
     * @return
     */
    public String getContextName() {
        return contextName;
    }

    public void setContextName(String contextName) {
        this.contextName = contextName;
    }
}
