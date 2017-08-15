package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.security.core.Logable;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.server.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.LdapContext;
import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/26/16 at  3:32 PM
 */
public class LDAPScopeHandler extends BasicScopeHandler implements Logable {

    public LDAPScopeHandler(LDAPConfiguration ldapConfiguration, MyLoggingFacade myLogger) {
        this.ldapConfiguration = ldapConfiguration;
        this.myLogger = myLogger;
        if (myLogger != null) {
            loggingEnabled = true;
        }
    }

    protected boolean loggingEnabled = false;

    public LDAPScopeHandler(OA2SE oa2SE) {
        super(oa2SE);
        this.myLogger = oa2SE.getMyLogger();
        loggingEnabled = (this.myLogger!=null);
    }


    /**
     * Returns the name of the user for whom the search is to be run. The default is to return the name the user used
     * to log in to MyProxy. Otherwise, this takes a key for the user information and returns the value it finds there.
     * Note that if you specify an email, the whole email will be returned. Otherwise, the name will be truncated
     * at the "@" sign (e.g. like an eppn).
     *
     * @param userInfo
     * @param request
     * @param transaction
     * @return
     */
    public String getSearchName(UserInfo userInfo, HttpServletRequest request, ServiceTransaction transaction) {

      /*  if (ServletDebugUtil.isEnabled()) {
            userInfo.getMap().put(getCfg().getSearchNameKey(), "jgaynor@ncsa.illinois.edu");
            userInfo.getMap().put("eppn", "jgaynor@ncsa.illinois.edu");
            //  userInfo.getMap().put("username", "http://cilogon.org/serverA/users/10376");
            //return "http://cilogon.org/serverA/users/10376";
        }*/
        // END debugging hack.
        JSONObject xxx = LDAPConfigurationUtil.toJSON(getCfg());
        xxx.getJSONObject("ldap").getJSONObject("ssl").put("keystore", "");
        if (getCfg().getSearchNameKey() == null) {
            warn("No search name given for LDAP query. Using default of username");
            return transaction.getUsername();
        }
        if (getCfg().getSearchNameKey().equals(LDAPConfigurationUtil.SEARCH_NAME_USERNAME)) {
            return transaction.getUsername();
        }
        if (!userInfo.getMap().containsKey(getCfg().getSearchNameKey()) || userInfo.getMap().get(getCfg().getSearchNameKey()) == null) {
            throw new IllegalStateException("Error: no recognized search name key was found. Requested was \"" + getCfg().getSearchNameKey() + "\"");
        }
        String searchName = (String) userInfo.getMap().get(getCfg().getSearchNameKey());

        if (getCfg().getServer().equals("ldap.ncsa.illinois.edu")) {
            DebugUtil.dbg(this, "Getting search name for NCSA LDAP");

            //searchName = (String) userInfo.getMap().get(CILogonScopeHandler.CILogonClaims.EPPN);
            searchName = (String) userInfo.getMap().get(getCfg().getSearchNameKey());
            searchName = searchName.substring(0, searchName.indexOf("@")); // take the name from the eppn
            // This is to look in the NCSA's LDAP handler
        }

/*
        if(!getCfg().getSearchNameKey().equals(OA2Claims.EMAIL)) {
            // Use the name on the email address, not the whole email addrress
            searchName = searchName.substring(0, searchName.indexOf("@")); // take the name from the email
        }
*/
        return searchName;
    }

    MyLoggingFacade myLogger = null;

    protected MyLoggingFacade getMyLogger() {
        return myLogger;
    }

    public void handleException(Throwable throwable) {
        if (throwable instanceof CommunicationException) {
            warn("Communication exception talking to LDAP.");

            return;
        }
        if (getCfg().isFailOnError()) {
            String subjectTemplate = "Error on ${host} contacting LDAP server";
            String messageTemplate = "The following error message was received attempting to contact the " +
                    "LDAP server at ${ldap_host}:\n\n${message}\n\n. The operation did not complete.";
            Map<String, String> replacements = new HashMap<>();
            URI address = getOa2SE().getServiceAddress();
            String x = "localhost";
            if (address != null) {
                x = address.getHost();
            }
            replacements.put("host", x);
            replacements.put("ldap_host", getCfg().getServer());
            replacements.put("message", throwable.getMessage());
            if (getCfg().isNotifyOnFail()) {
                getOa2SE().getMailUtil().sendMessage(subjectTemplate, messageTemplate, replacements);
            }
            throw new GeneralException("Error: Could not communicate with LDAP server. \"" + throwable.getMessage() + "\"");
        }

    }

    @Override
    public boolean isEnabled() {
        return getCfg().isEnabled();
    }

    @Override
    synchronized public UserInfo process(UserInfo userInfo, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        if (!isEnabled()) {
            DebugUtil.dbg(this, "server=" + getCfg().getServer() + ", is NOT enabled.");
            return userInfo;
        }

        DebugUtil.dbg(this, "Starting LDAP query");
        DebugUtil.dbg(this, "target host =" + getCfg().getServer());

        if (!isLoggedOn()) {
            logon();
        }
        DebugUtil.dbg(this, "   logged on");
        DebugUtil.dbg(this, "Claims=" + getClaims());
        try {
            String searchName = getSearchName(userInfo, request, transaction);
            DebugUtil.dbg(this, "  search name=" + searchName);

            if (searchName != null) {
                Map tempMap = simpleSearch(context, searchName, getCfg().getSearchAttributes());
                DebugUtil.dbg(this,"returned from search:" + tempMap);
                userInfo.getMap().putAll(tempMap);
            } else {
                info("No search name encountered for LDAP query. No search performed.");
            }
            DebugUtil.dbg(this, "user info =" + userInfo.getMap());

            context.close();
        } catch (Throwable throwable) {
            handleException(throwable);
        } finally {
            closeConnection();
        }
        return userInfo;
    }


    protected boolean isLoggedOn() {
        return context != null;
    }

    LdapContext context;

    LDAPConfiguration ldapConfiguration = null;

    protected LDAPConfiguration getCfg() {
        if (ldapConfiguration == null) {
            ldapConfiguration = getOa2SE().getLdapConfiguration();
        }
        return ldapConfiguration;
    }

    protected boolean logon() {
        try {
        /*    if (getCfg().getSslConfiguration() != null) {
                if (getCfg().getSslConfiguration().getTrustrootPath() != null) {
                    System.setProperty("javax.net.ssl.trustStore", getCfg().getSslConfiguration().getTrustrootPath());
                    System.setProperty("javax.net.ssl.trustStorePassword", getCfg().getSslConfiguration().getTrustRootPassword());
                    System.setProperty("javax.net.ssl.trustStoreType", getCfg().getSslConfiguration().getTrustRootType());
                }
            }*/


            // Set up the environment for creating the initial context
            Hashtable<String, String> env = new Hashtable<String, String>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
       //     env.put("java.naming.ldap.factory.socket", "edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.LDAPSSLSocketFactory");

            String providerUrl = "ldaps://" + getCfg().getServer();
            if (0 <= getCfg().getPort()) {
                providerUrl = providerUrl + ":" + getCfg().getPort();
            }
            env.put(Context.PROVIDER_URL, providerUrl);
            switch (getCfg().getAuthType()) {
                case LDAPConfigurationUtil.LDAP_AUTH_NONE_KEY:
                    env.put(Context.SECURITY_AUTHENTICATION, LDAPConfigurationUtil.LDAP_AUTH_NONE);
                    env.put(Context.SECURITY_PROTOCOL, "ssl");

                    break;
                case LDAPConfigurationUtil.LDAP_AUTH_SIMPLE_KEY:
                    env.put(Context.SECURITY_AUTHENTICATION, LDAPConfigurationUtil.LDAP_AUTH_SIMPLE);
                    env.put(Context.SECURITY_PRINCIPAL, getCfg().getSecurityPrincipal());
                    env.put(Context.SECURITY_CREDENTIALS, getCfg().getPassword());
                    env.put(Context.SECURITY_PROTOCOL, "ssl");
                    break;
                case LDAPConfigurationUtil.LDAP_AUTH_STRONG_KEY:
                    env.put(Context.SECURITY_AUTHENTICATION, LDAPConfigurationUtil.LDAP_AUTH_STRONG);
                    env.put(Context.SECURITY_PRINCIPAL, getCfg().getSecurityPrincipal());
                    env.put(Context.SECURITY_CREDENTIALS, getCfg().getPassword());
                    env.put(Context.SECURITY_PROTOCOL, "ssl");
                    break;
                default:
                case LDAPConfigurationUtil.LDAP_AUTH_UNSPECIFIED_KEY:
            }
             DebugUtil.dbg(this, "LDAP environment is " + env);
            DirContext dirContext = new InitialDirContext(env);
            context = (LdapContext) dirContext.lookup(getCfg().getSearchBase());
            return context != null;
        } catch (Exception e) {
            if (isDebugOn()) {
                e.printStackTrace();
            }
            error("Error logging into LDAP server", e);
            return false;
        }
    }

    @Override
    public Collection<String> getClaims() {
        Collection<String> claims = super.getClaims();
        for (String key : getCfg().getSearchAttributes().keySet()) {
            LDAPConfigurationUtil.AttributeEntry ae = getCfg().getSearchAttributes().get(key);
            claims.add(ae.targetName);
        }
        return claims;
    }

    // STOP GAP. This should be given in the LDAPConfiguration and is the name of the attribute (e.g. uid, email)
    // that is used for searching. It's compliment is the searchFilterValue, so
    // searchFilterAttribute=searchFilterValue
    //e.g, uid=eppn
    // The searchFilterValue is supplied in the initial claims.
    protected String getSearchFilterAttribute() {
        return "uid";
    }

    protected JSONObject simpleSearch(LdapContext ctx,
                                      String userID,
                                      Map<String, LDAPConfigurationUtil.AttributeEntry> attributes) throws NamingException {
        if (ctx == null) {
            throw new IllegalStateException("Error: Could not create the LDAP context");
        }
        DebugUtil.dbg(this, "starting simple LDAP search");
        SearchControls ctls = new SearchControls();
        if (attributes == null || attributes.isEmpty()) {
            // return everything if nothing is specified.
            ctls.setReturningAttributes(null);
        } else {
            String[] searchAttributes = attributes.keySet().toArray(new String[]{});
            ctls.setReturningAttributes(searchAttributes);
        }
        //ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String filter = "(&(" + getSearchFilterAttribute() + "=" + userID + "))";
        DebugUtil.dbg(this, "filter=" + filter);
        NamingEnumeration e = ctx.search(getCfg().getContextName(), filter, ctls);
        return toJSON(attributes, e);
    }

    /**
     * This takes the result of the search as a {@link NamingEnumeration} and set of attributes (from the
     * configuration file) and returns a JSON object. The default is that singletons are returned as simple
     * values while lists are recorded as arrays.
     *
     * @param attributes
     * @param e
     * @return
     * @throws NamingException
     */
    protected JSONObject toJSON(Map<String, LDAPConfigurationUtil.AttributeEntry> attributes, NamingEnumeration e) throws NamingException {
        DebugUtil.dbg(this, "starting to convert search results to JSON. " + attributes.size() + " results found.");
        JSONObject json = new JSONObject();

        while (e.hasMore()) {
            SearchResult entry = (SearchResult) e.next();
            Attributes a = entry.getAttributes();
            System.out.println(entry.getName());
            for (String attribID : attributes.keySet()) {
                Attribute attribute = a.get(attribID);
                DebugUtil.dbg(this, "returned LDAP attribute=" + attribute);
                if (attribute == null) {
                    continue;
                }
                if (attribute.size() == 1) {
                    // Single-valued attributes are recorded as simple values
                    if (attributes.get(attribID).isList) {
                        JSONArray jsonAttribs = new JSONArray();
                        jsonAttribs.add(attribute.get(0));
                        json.put(attributes.get(attribID).targetName, jsonAttribs);
                    } else {
                        json.put(attributes.get(attribID).targetName, attribute.get(0));
                    }
                } else {
                    // Multi-valued attributes are recorded as arrays.
                    JSONArray jsonAttribs = new JSONArray();
                    for (int i = 0; i < attribute.size(); i++) {
                        jsonAttribs.add(attribute.get(i));
                    }
                    json.put(attributes.get(attribID).targetName, jsonAttribs);
                }
            }
        }
        DebugUtil.dbg(this, "LDAP search results=" + json);
        return json;
    }

    protected void closeConnection() {
        if (context != null) {
            try {
                context.close();
            } catch (Throwable t) {
                if (isDebugOn()) {
                    t.printStackTrace();
                }
                info("Exception trying to close LDAP connection: " + t.getMessage());
            }
        }
    }

    protected void sayit(String x) {
        System.out.println(x);
    }

    @Override
    public void debug(String x) {
        if (loggingEnabled) {
            getMyLogger().debug(x);
        } else {
            sayit(x);
        }
    }

    @Override
    public boolean isDebugOn() {
        if (loggingEnabled) {
            return getMyLogger().isDebugOn();
        }
        return debug;
    }

    boolean debug = false;

    @Override
    public void setDebugOn(boolean setOn) {
        if (loggingEnabled) {
            getMyLogger().setDebugOn(setOn);
        }
        this.debug = setOn;
    }

    @Override
    public void info(String x) {
        if (loggingEnabled) {
            getMyLogger().info(x);
        } else {
            sayit(x);
        }

    }

    @Override
    public void warn(String x) {
        if (loggingEnabled) {
            getMyLogger().warn(x);
        } else {
            sayit(x);
        }

    }

    public void error(String x, Throwable e) {
        if (loggingEnabled) {
            getMyLogger().error(x, e);
        } else {
            sayit(x);
            e.printStackTrace();
        }

    }

    @Override
    public void error(String x) {
        if (loggingEnabled) {
            getMyLogger().error(x);
        } else {
            sayit(x);
        }

    }

    @Override
    public String toString() {
        return "LDAPScopeHandler{" +
                (ldapConfiguration == null?"(no config)":ldapConfiguration.getServer())+"}";
    }
}
