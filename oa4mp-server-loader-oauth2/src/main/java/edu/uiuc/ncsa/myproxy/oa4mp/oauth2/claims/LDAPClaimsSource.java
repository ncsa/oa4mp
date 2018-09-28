package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.GroupHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.NCSAGroupHandler;
import edu.uiuc.ncsa.security.core.Logable;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
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
public class LDAPClaimsSource extends BasicClaimsSourceImpl implements Logable {
    public LDAPClaimsSource() {
    }

    public LDAPClaimsSource(LDAPConfiguration ldapConfiguration, MyLoggingFacade myLogger) {
        super();
        if (ldapConfiguration == null) {
            throw new IllegalArgumentException("Error: null ldap config");
        }
        setConfiguration(ldapConfiguration);
        this.myLogger = myLogger;
        if (myLogger != null) {
            loggingEnabled = true;
        }
    }

    protected boolean loggingEnabled = false;


    public LDAPClaimsSource(OA2SE oa2SE) {
        super(oa2SE);
        if (oa2SE == null) {
            throw new IllegalArgumentException("Error: null service env");
        }
        this.myLogger = oa2SE.getMyLogger();
        loggingEnabled = (this.myLogger != null);
    }


    /**
     * Returns the name of the user for whom the search is to be run. The default is to return the name the user used
     * to log in to MyProxy. Otherwise, this takes a key for the user information and returns the value it finds there.
     * Note that if you specify an email, the whole email will be returned. Otherwise, the name will be truncated
     * at the "@" sign (e.g. like an eppn).
     *
     * @param claims
     * @param request
     * @param transaction
     * @return
     */
    public String getSearchName(JSONObject claims, HttpServletRequest request, ServiceTransaction transaction) {
        DebugUtil.dbg(this, "starting to get search name");
        LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();
        JSONObject xxx = ldapConfigurationUtil.toJSON(getLDAPCfg());
        xxx.getJSONObject("ldap").getJSONObject("ssl").put("keystore", "");
        if (getLDAPCfg().getSearchNameKey() == null) {
            DebugUtil.dbg(this, "No search name given for LDAP query. Using default of username " + transaction.getUsername());

            warn("No search name given for LDAP query. Using default of username");
            return transaction.getUsername();
        }
        if (getLDAPCfg().getSearchNameKey().equals(LDAPConfigurationUtil.SEARCH_NAME_USERNAME)) {
            return transaction.getUsername();
        }
        if (!claims.containsKey(getLDAPCfg().getSearchNameKey()) || claims.get(getLDAPCfg().getSearchNameKey()) == null) {
            String message = "Error: no recognized search name key was found. Requested was \"" + getLDAPCfg().getSearchNameKey() + "\"";
            getMyLogger().warn(message);
            throw new IllegalStateException(message);
        }
        String searchName = (String) claims.get(getLDAPCfg().getSearchNameKey());
        DebugUtil.dbg(this, "returning search name=" + searchName);

        return searchName;
    }

    protected boolean isNCSA() {
        return getLDAPCfg().getServer().endsWith(".ncsa.illinois.edu");
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
        if (getLDAPCfg().isFailOnError()) {
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
            replacements.put("ldap_host", getLDAPCfg().getServer());
            replacements.put("message", throwable.getMessage());
            if (getLDAPCfg().isNotifyOnFail()) {
                getOa2SE().getMailUtil().sendMessage(subjectTemplate, messageTemplate, replacements);
            }
            throw new GeneralException("Error: Could not communicate with LDAP server. \"" + throwable.getMessage() + "\"");
        }

    }

    protected Groups processNCSAGroups() {
        Groups groups = new Groups();

        return groups;
    }

    @Override
    public boolean isEnabled() {
        if (getConfiguration() == null) {
            return false; // for an LDAP source, no configuration should mean this does nto run.
        }
        return super.isEnabled();
    }

    @Override
    protected JSONObject realProcessing(JSONObject claims, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        if (!isEnabled()) {
            DebugUtil.dbg(this, "server=" + getLDAPCfg().getServer() + ", is NOT enabled.");
            return claims;
        }

        DebugUtil.dbg(this, "Starting LDAP query!");
        DebugUtil.dbg(this, "target host =" + getLDAPCfg().getServer());

        if (!isLoggedOn()) {
            logon();
        }
        DebugUtil.dbg(this, "   logged on? " + isLoggedOn());
        DebugUtil.dbg(this, "Claims =" + getClaims());
        try {
            String searchName = getSearchName(claims, request, transaction);
            DebugUtil.dbg(this, "  search name=" + searchName);

            if (searchName != null) {
                Map tempMap = simpleSearch(context, searchName, getLDAPCfg().getSearchAttributes());
                DebugUtil.dbg(this, "returned from search:" + tempMap);
                claims.putAll(tempMap);
            } else {
                info("No search name encountered for LDAP query. No search performed.");
            }
            DebugUtil.dbg(this, "claims =" + claims);
            context.close();
        } catch (Throwable throwable) {
            DebugUtil.dbg(this, "Error getting search name \"" + throwable.getMessage() + "\"", throwable);
            handleException(throwable);
        } finally {
            closeConnection();
        }
        return claims;
    }


    protected boolean isLoggedOn() {
        return context != null;
    }

    public LdapContext context;


    /**
     * Convenience to cast the configuration to the right class.
     *
     * @return
     */
    public LDAPConfiguration getLDAPCfg() {
        return (LDAPConfiguration) getConfiguration();
    }


    public boolean logon() {
        context = createConnection();
        return context != null;

    }

    public Hashtable<String, String> createEnv(LDAPConfiguration cfg) {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        String providerUrl = "ldaps://" + cfg.getServer();
        if (0 <= cfg.getPort()) {
            providerUrl = providerUrl + ":" + cfg.getPort();
        }
        env.put(Context.PROVIDER_URL, providerUrl);
        switch (cfg.getAuthType()) {
            case LDAPConfigurationUtil.LDAP_AUTH_NONE_KEY:
                env.put(Context.SECURITY_AUTHENTICATION, LDAPConfigurationUtil.LDAP_AUTH_NONE);
                env.put(Context.SECURITY_PROTOCOL, "ssl");

                break;
            case LDAPConfigurationUtil.LDAP_AUTH_SIMPLE_KEY:
                env.put(Context.SECURITY_AUTHENTICATION, LDAPConfigurationUtil.LDAP_AUTH_SIMPLE);
                env.put(Context.SECURITY_PRINCIPAL, cfg.getSecurityPrincipal());
                env.put(Context.SECURITY_CREDENTIALS, cfg.getPassword());
                env.put(Context.SECURITY_PROTOCOL, "ssl");
                break;
            case LDAPConfigurationUtil.LDAP_AUTH_STRONG_KEY:
                env.put(Context.SECURITY_AUTHENTICATION, LDAPConfigurationUtil.LDAP_AUTH_STRONG);
                env.put(Context.SECURITY_PRINCIPAL, cfg.getSecurityPrincipal());
                env.put(Context.SECURITY_CREDENTIALS, cfg.getPassword());
                env.put(Context.SECURITY_PROTOCOL, "ssl");
                break;
            default:
            case LDAPConfigurationUtil.LDAP_AUTH_UNSPECIFIED_KEY:
        }
        DebugUtil.dbg(this, "LDAP environment is " + env);
        return env;
    }

    public LdapContext createConnection() {
        try {
            // Set up the environment for creating the initial context

            DirContext dirContext = new InitialDirContext(createEnv(getLDAPCfg()));
            return (LdapContext) dirContext.lookup(getLDAPCfg().getSearchBase());
        } catch (Exception e) {
            if (isDebugOn()) {
                e.printStackTrace();
            }
            error("Error logging into LDAP server", e);
            return null;
        }
    }

    @Override
    public Collection<String> getClaims() {
        Collection<String> claims = super.getClaims();
        for (String key : getLDAPCfg().getSearchAttributes().keySet()) {
            LDAPConfigurationUtil.AttributeEntry ae = getLDAPCfg().getSearchAttributes().get(key);
            claims.add(ae.targetName);
        }
        return claims;
    }

    // This is given in the LDAPConfiguration and is the name of the attribute (e.g. uid, email)
    // that is used for searching. It's compliment is the searchFilterValue, so
    // searchFilterAttribute=searchFilterValue
    //e.g, uid=eppn
    // The searchFilterValue is supplied in the initial claims.
    protected String getSearchFilterAttribute() {
        ServletDebugUtil.dbg(this, "search attribute in LDAP is " + getLDAPCfg().getSearchFilterAttribute());
        if(getLDAPCfg().getSearchFilterAttribute() == null){
            return LDAPConfigurationUtil.SEARCH_FILTER_ATTRIBUTE_DEFAULT; // default
        }else {
            return getLDAPCfg().getSearchFilterAttribute();
        }
    }

    public JSONObject simpleSearch(LdapContext ctx,
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
        NamingEnumeration e = ctx.search(getLDAPCfg().getContextName(), filter, ctls);
        return toJSON(attributes, e, userID);
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
    protected JSONObject toJSON(Map<String,
            LDAPConfigurationUtil.AttributeEntry> attributes,
                                NamingEnumeration e,
                                String userName) throws NamingException {
        DebugUtil.dbg(this, "starting to convert search results to JSON. " + attributes.size() + " results requested.");
        JSONObject json = new JSONObject();
        if (!e.hasMoreElements()) {
            DebugUtil.dbg(this, "LDAP SEARCH RESULT IS EMPTY");
        }
        while (e.hasMoreElements()) {
            SearchResult entry = (SearchResult) e.next();
            Attributes a = entry.getAttributes();
            for (String attribID : attributes.keySet()) {
                DebugUtil.dbg(this, "returned LDAP attrib ID=" + attribID);
                Attribute attribute = a.get(attribID);
                DebugUtil.dbg(this, "returned LDAP attribute=" + attribute);
                if (attribute == null) {
                    continue;
                }
                if (attributes.get(attribID).isGroup) {
                    JSONArray jsonAttribs = new JSONArray();
                    for (int i = 0; i < attribute.size(); i++) {
                        jsonAttribs.add(attribute.get(i));
                    }
                    GroupHandler gg = null;
                    if (isNCSA()) {
                        gg = new NCSAGroupHandler(this, userName);
                    } else {
                        gg = getGroupHandler();
                    }
                    Groups groups = gg.parse(jsonAttribs);
                    json.put(attributes.get(attribID).targetName, groups.toJSON());
                } else {
                    if (attribute.size() == 1) {
                        // Single-valued attributes are recorded as simple values
                        if (attributes.get(attribID).isList) {
                            // Convert a single value to a JSON array.
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
        System.err.println(x);
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
        return "LDAPClaimsSource{" +
                (configuration == null ? "(no config)" : configuration.getName()) + "}";
    }

    public static void main(String[] args) {
        try {
            String rawLdap = "{\"ldap\":{\"failOnError\":\"false\"," +
                    "\"address\":\"ldap.ncsa.illinois.edu\"," +
                    "\"port\":636," +
                    "\"enabled\":\"true\"," +
                    "\"authorizationType\":\"none\"," +
                    "\"searchName\":\"eppn\"," +
                    "\"searchAttributes\":[{" +
                    "\"name\":\"mail\"," +
                    "\"returnAsList\":false," +
                    "\"returnName\":\"mail\"}," +
                    "{\"name\":\"cn\"," +
                    "\"returnAsList\":false," +
                    "\"returnName\":\"name\"}," +
                    "{\"name\":\"memberOf\"," +
                    "\"returnAsList\":false," +
                    "\"isGroup\":true," +
                    "\"returnName\":\"isMemberOf\"}]," +
                    "\"searchBase\":\"ou=People,dc=ncsa,dc=illinois,dc=edu\"," +
                    "\"contextName\":\"\"," +
                    "\"ssl\":{\"tlsVersion\":\"TLS\",\"useJavaTrustStore\":true}}}";
            String rawLdap2 = "{\"ldap\": {\n" +
                    "  \"address\": \"registry-test.cilogon.org\",\n" +
                    "  \"port\": 636,\n" +
                    "  \"enabled\": true,\n" +
                    "  \"authorizationType\": \"simple\",\n" +
                    "  \"failOnError\": false,\n" +
                    "  \"notifyOnFail\": false,\n" +
                    "  \"password\": \"Eavjofoop4gikpecUzbooljorUryikwu\",\n" +
                    "  \"principal\": \"uid=oa4mp_user,ou=system,o=ImPACT,dc=cilogon,dc=org\",\n" +
                    "  \"searchAttributes\":   [\n" +
                    "        {\n" +
                    "      \"name\": \"isMemberOf\",\n" +
                    "      \"returnAsList\": true,\n" +
                    "      \"returnName\": \"isMemberOf\"\n" +
                    "    },\n" +
                    "        {\n" +
                    "      \"name\": \"employeeNumber\",\n" +
                    "      \"returnAsList\": false,\n" +
                    "      \"returnName\": \"employeeNumber\"\n" +
                    "    }\n" +
                    "  ],\n" +
                    "  \"searchBase\": \"ou=people,o=ImPACT,dc=cilogon,dc=org\",\n" +
                    "  \"searchName\": \"username\",\n" +
                    "  \"contextName\": \"\",\n" +
                    "  \"ssl\":   {\n" +
                    "    \"keystore\": {},\n" +
                    "    \"useJavaTrustStore\": true,\n" +
                    "    \"password\": \"changeit\",\n" +
                    "    \"type\": \"jks\"\n" +
                    "  }\n" +
                    "}}";
            DebugUtil.setIsEnabled(true);
            ServiceTransaction st = new ServiceTransaction(BasicIdentifier.newID("foo"));
            st.setUsername("jbasney@ncsa.illinois.edu");
            JSONObject json = JSONObject.fromObject(rawLdap);
            LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();
            LDAPConfiguration cfg = ldapConfigurationUtil.fromJSON(json);
            LDAPClaimsSource claimsSource = new LDAPClaimsSource(cfg, null);
            JSONObject claims = new JSONObject();
            claims.put("username", "jbasney@ncsa.illinois.edu");
            claims.put("eppn", "jbasney@ncsa.illinois.edu");
            JSONObject ui2 = claimsSource.process(claims, st);
            System.out.println("Result of LDAP query:");
            System.out.println(ui2);
            //   getGid(cfg, "lsst_users");
        } catch (Throwable t) {
            t.printStackTrace();

        }
    }


    public static Groups get_NEW_Gid(LDAPConfiguration cfg2, String username) throws Throwable {
        LDAPConfiguration cfg = cfg2.clone();
        cfg.setSearchBase("ou=Groups,dc=ncsa,dc=illinois,dc=edu");
        ServletDebugUtil.dbg(LDAPClaimsSource.class, "LDAP search is: " + cfg.getSearchFilterAttribute() + "=" + username);
        LDAPClaimsSource claimsSource = new LDAPClaimsSource(cfg, null);
        DirContext dirContext = new InitialDirContext(claimsSource.createEnv(cfg));
        LdapContext ctx = (LdapContext) dirContext.lookup(cfg.getSearchBase());
        SearchControls ctls = new SearchControls();
        ctls.setReturningAttributes(new String[]{"cn", "gidNumber"});
        String filter = "(&(uniqueMember=" + cfg.getSearchFilterAttribute() + "=" + username + ",ou=People,dc=ncsa,dc=illinois,dc=edu))";
        ServletDebugUtil.dbg(LDAPClaimsSource.class, "LDAP filter=" + filter);

        NamingEnumeration e = ctx.search(cfg.getContextName(), filter, ctls);
        Groups groups = new Groups();
        ServletDebugUtil.dbg(LDAPClaimsSource.class, "Starting to process groups. Has elements? " + e.hasMoreElements() );

        while (e.hasMoreElements()) {
            SearchResult entry = (SearchResult) e.next();
            Attributes a = entry.getAttributes();
            GroupElement groupElement = convertToEntry(a);
            ServletDebugUtil.dbg(LDAPClaimsSource.class, "Added group element = " + groupElement);

            groups.put(groupElement);
        }
        ctx.close();
        return groups;
    }

    protected static GroupElement convertToEntry(Attributes a) throws NamingException {
        JSONObject json = new JSONObject();
        Attribute attribute = a.get("gidNumber");

        int gid = -1;
        if (attribute != null) {
            String xxx = String.valueOf(attribute.get(0));
            if (xxx != null && !xxx.isEmpty()) {
                gid = Integer.parseInt(xxx);
            }

        }
        if (-1 < gid) {
            json.put("id", gid);
        }
        attribute = a.get("cn");
        String id = attribute.getID() + ":"; // standard format

        String groupName = attribute.toString().substring(id.length()).trim();
        if (groupName.isEmpty()) {
            throw new NFWException("Error: The group name somehow was empty. This implies the LDAP entry has changed or is incorrect");
        }
        GroupElement g = null;
        if (gid == -1) {
            // no gid
            g = new GroupElement(groupName);
        } else {
            g = new GroupElement(groupName, gid);
        }

        return g;

    }

    public static int get_OLD_Gid(LDAPConfiguration cfg2, String groupName) throws Throwable {
        LDAPConfiguration cfg = cfg2.clone();
        cfg.setSearchBase("ou=Groups,dc=ncsa,dc=illinois,dc=edu");
        LDAPClaimsSource claimsSource = new LDAPClaimsSource(cfg, null);
        DirContext dirContext = new InitialDirContext(claimsSource.createEnv(cfg));
        LdapContext ctx = (LdapContext) dirContext.lookup(cfg.getSearchBase());
        SearchControls ctls = new SearchControls();
        ctls.setReturningAttributes(new String[]{"gidNumber"});
        String filter = "(&(cn=" + groupName + "))";
        NamingEnumeration e = ctx.search(cfg.getContextName(), filter, ctls);
        while (e.hasMoreElements()) {
            SearchResult entry = (SearchResult) e.next();
            Attributes a = entry.getAttributes();

            Attribute attribute = a.get("gidNumber");
            if (attribute == null) {
                continue;
            }
            String xxx = String.valueOf(attribute.get(0));
            if (xxx != null && !xxx.isEmpty()) {
                ctx.close();
                return Integer.parseInt(xxx);
            }
        }
        return -1;
    }

}
