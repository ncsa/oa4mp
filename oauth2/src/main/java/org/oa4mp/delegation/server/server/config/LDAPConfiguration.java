package org.oa4mp.delegation.server.server.config;

import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import net.sf.json.JSONObject;

import javax.naming.Name;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapContext;
import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/3/16 at  11:17 AM
 */
public class LDAPConfiguration extends JSONClaimSourceConfig {
    /*
      This acts like a JSONClaimSourceConfig object, but is not backed by a JSONObject.
     */
    public LDAPConfiguration() {
        super(null);
    }

    String server;
    int port = -1;
    SSLConfiguration sslConfiguration;


    public String getSearchNameKey() {
        return searchNameKey;
    }

    public void setSearchNameKey(String searchNameKey) {
        this.searchNameKey = searchNameKey;
    }

    String searchNameKey;
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

    Map<String,LDAPConfigurationUtil.AttributeEntry> searchAttributes = new HashMap<>();

    /**
     * Search attributes are recorded as a map. The key  is the search term in the LDAP query. The value
     * is the name that should be returned for this attribute in the claim.
     * @return
     */
    public Map<String,LDAPConfigurationUtil.AttributeEntry> getSearchAttributes() {
        return searchAttributes;
    }

    public void setSearchAttributes(Map<String,LDAPConfigurationUtil.AttributeEntry> searchAttributes) {
        this.searchAttributes = searchAttributes;
    }

    public String getSearchFilterAttribute() {
        return searchFilterAttribute;
    }

    public void setSearchFilterAttribute(String searchFilterAttribute) {
        this.searchFilterAttribute = searchFilterAttribute;
    }

    String searchFilterAttribute = "uid"; // DEFAULT!!!

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    String password;

    public int getPort() {
        return port;
    }

    public void setPort(int  port) {
        this.port = port;
    }

    /**
     * This is a raw string of addresses (possibly plural) all comma separated. Each address will be checked in sequence.
     * The idea is that there are multiple LDAP servers with identical configurations that have difference addresses in
     * case of failure (e.g.ldap1.ncsa.illinois.edu, ladp2.ncsa.illinois.edu) and the contract is that if there are multiple
     * addresses here, they will be sequentially checked until one of them works and then the LDAP claim source is deemed
     * done. Only in the case that <b>all</b> the addresses fail is a failure raised. 
     * @return
     */
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


    @Override
    public boolean equals(Object obj) {
        if(!(obj instanceof LDAPConfiguration)) return false;
        LDAPConfiguration ldap = (LDAPConfiguration) obj;
        if(!checkEquals(ldap.getContextName(), getContextName())) return false;
        if(!checkEquals(ldap.getPassword(), getPassword())) return false;
        if(!checkEquals(ldap.getSecurityPrincipal(), getSecurityPrincipal())) return false;
        if(!checkEquals(ldap.getSearchBase(), getSearchBase())) return false;
        if(!checkEquals(ldap.getServer(), getServer())) return false;
        if(ldap.getPort() != getPort()) return false;
        if(ldap.getAuthType() != getAuthType()) return false;
        if(!ldap.getSslConfiguration().equals(getSslConfiguration())) return false;
        return true;
    }

    @Override
    public LDAPConfiguration clone() throws CloneNotSupportedException {
        LDAPConfiguration ldap2 = new LDAPConfiguration();
        ldap2.setAuthType(getAuthType());
        ldap2.setContextName(getContextName());
        ldap2.setEnabled(isEnabled());
        ldap2.setFailOnError(isFailOnError());
        ldap2.setNotifyOnFail(isNotifyOnFail());
        ldap2.setPassword(getPassword());
        ldap2.setPort(getPort());
        ldap2.setSearchAttributes(getSearchAttributes());
        ldap2.setSearchNameKey(getSearchNameKey());
        ldap2.setSecurityPrincipal(getSecurityPrincipal());
        ldap2.setServer(getServer());
        ldap2.setSslConfiguration(getSslConfiguration());
        ldap2.setSearchBase(getSearchBase());
        ldap2.setRawPostProcessor(getRawPostProcessor());
        ldap2.setRawPreProcessor(getRawPreProcessor());
        ldap2.setSearchFilterAttribute(getSearchFilterAttribute());
        ldap2.setAdditionalFilter(getAdditionalFilter());
        return ldap2;
    }

    @Override
    public String toString() {
        return "LDAPConfiguration{" +
                "authType=" + authType +
                ", server='" + server + '\'' +
                ", port=" + port +
                ", sslConfiguration=" + sslConfiguration +
                ", searchNameKey='" + searchNameKey + '\'' +
                ", securityPrincipal='" + securityPrincipal + '\'' +
                ", searchBase='" + searchBase + '\'' +
                ", searchAttributes=" + searchAttributes +
                ", enabled=" + enabled +
                ", password='" + password + '\'' +
                ", contextName='" + contextName + '\'' +
                ", failOnError=" + failOnError +
                ", notifyOnFail=" + notifyOnFail +
                ", additionalFilter=" + additionalFilter + 
                '}';
    }

    public String getSearchScope() {
        return searchScope;
    }

    public void setSearchScope(String searchScope) {
        this.searchScope = searchScope;
    }

    String searchScope;

    public boolean hasSearchScope(){
        return searchScope!=null && searchScope.trim().length()!=0;
    }
    /**
     * This is used as part of the search filter. A normal one would be
     * <pre>
     *     ((&amp; + {@link #getSearchFilterAttribute} + claim + )({@link #getAdditionalFilter}))
     * </pre>
     * So one might look like
     * <pre>
     *     (&amp;(uid=bob)(isMemberOf=Communities:LVC:SegDB:SegDBWriter))
     * </pre>
     * Generally this will be dropped verbatim in the slot, so include parentheses.
     * @return
     */
    public String getAdditionalFilter() {
        return additionalFilter;
    }

    public void setAdditionalFilter(String additionalFilter) {
        this.additionalFilter = additionalFilter;
    }

    String additionalFilter;
    @Override
    public void fromJSON(JSONObject json) {
        LDAPConfigurationUtil x = new LDAPConfigurationUtil();
        x.fromJSON(this, json);
    }

    @Override
    public JSONObject toJSON() {
        LDAPConfigurationUtil x = new LDAPConfigurationUtil();
        return x.toJSON(this);
    }

    @Override
    public boolean hasJSONObject() {
        return true;
    }

}
