package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.GroupHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.NCSAGroupHandler;
import edu.uiuc.ncsa.security.core.Logable;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
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
import java.util.*;

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
        String dbgname = ".getSearchName(id=" + getLDAPCfg().getId() + "):";
        DebugUtil.trace(this, dbgname);
        LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();
        JSONObject xxx = ldapConfigurationUtil.toJSON(getLDAPCfg());
        if(xxx.getJSONObject("ldap").containsKey("ssl")) {
            xxx.getJSONObject("ldap").getJSONObject("ssl").put("keystore", "");
        }
        if (getLDAPCfg().getSearchNameKey() == null) {
            warn(dbgname + "No search name given for LDAP query. Using default of username");
            return transaction.getUsername();
        }
        if (getLDAPCfg().getSearchNameKey().equals(LDAPConfigurationUtil.SEARCH_NAME_USERNAME)) {
            DebugUtil.trace(this, dbgname+" searching using the username");
            return transaction.getUsername();
        }
        if (!claims.containsKey(getLDAPCfg().getSearchNameKey()) || claims.get(getLDAPCfg().getSearchNameKey()) == null) {
            String message = "Error: no recognized search name key was found in the claims for config with id=" + getLDAPCfg().getId() +
                    ". Requested was \"" + getLDAPCfg().getSearchNameKey() + "\"";
            DebugUtil.trace(this, message);
            throw new IllegalStateException(message);
        }
        String searchName = (String) claims.get(getLDAPCfg().getSearchNameKey());
        if(searchName == null || searchName.isEmpty()){
            // If the configuration file has an error, this will be the one place it shows first.
            // Best to trap it here and fail rather than have LDAP do the query (which it will and
            // return nothing) and inexplicably have no result.
            throw new IllegalArgumentException("Error: no search name found for LDAP query.");
        }
        return searchName;
    }

    protected boolean isNCSA() {
        ServletDebugUtil.trace(this, "checking if is NCSA LDAP claims source for \"" + currentServerAddress + "\"");
        return currentServerAddress.endsWith(".ncsa.illinois.edu");
    }

    MyLoggingFacade myLogger = null;

    protected MyLoggingFacade getMyLogger() {
        return myLogger;
    }

    public void handleException(Throwable throwable) {
        ServletDebugUtil.error(this,"Error accessing LDAP", throwable);

        if (throwable instanceof CommunicationException) {
            warn("Communication exception talking to LDAP.");
            return;
        }
        if (getLDAPCfg().isFailOnError()) {
            String message = (throwable instanceof NullPointerException)?"(null pointer)": throwable.getMessage();
            getMyLogger().warn("Could not get LDAP information:" + message);
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

            throw new GeneralException("Error: Could not communicate with LDAP server. \"" + (throwable.getMessage()==null?"(no message)": throwable.getMessage())  + "\"");
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
        String name="realProcessing(id=" + getLDAPCfg().getId() + "):" ;

        DebugUtil.trace(this,name + " preparing to do processing.");
        DebugUtil.trace(this,name + " initial claims = " + claims);
        if (!isEnabled()) {
            DebugUtil.trace(this,name + " Claims source not enabled." );
            return claims;
        }

        if (!isLoggedOn()) {
            logon();
        }
        try {
            String searchName = getSearchName(claims, request, transaction);
            DebugUtil.trace(this,name + " search name=" + searchName);

            if (searchName != null) {
                Map tempMap = simpleSearch(context, searchName, getLDAPCfg().getSearchAttributes());
                claims.putAll(tempMap);
            } else {
                info("No search name encountered for LDAP query. No search performed.");
            }
            context.close();
        } catch (Throwable throwable) {
            DebugUtil.trace(this, name + " Error getting search name \"" + throwable.getMessage() + "\"", throwable);
            handleException(throwable);
        } finally {
            closeConnection();
        }
        ServletDebugUtil.trace(this, name + " claims=" + claims);

        return claims;
    }


    protected boolean isLoggedOn() {
        return context != null;
    }

    transient protected LdapContext context = null;


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

    public Hashtable<String, String> createEnv(String host, LDAPConfiguration cfg) {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        String providerUrl = host.trim();
        if(!host.startsWith("ldaps://")){
             providerUrl = "ldaps://" + providerUrl;
        }
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
        return env;
    }

    /**
     * This is needed later when checking which address was successful.
     */
   String currentServerAddress = null;
    public LdapContext createConnection() {
        // Set up the environment for creating the initial context
        StringTokenizer stringTokenizer = new StringTokenizer(getLDAPCfg().getServer(), ",");
        Throwable lastException;

        DirContext dirContext = null;
        while (stringTokenizer.hasMoreTokens()) {
            try {
                currentServerAddress = stringTokenizer.nextToken();
                dirContext = new InitialDirContext(createEnv(currentServerAddress, getLDAPCfg()));
                ServletDebugUtil.trace(this, "Found LDAP server for address=\"" + currentServerAddress +"\"");
                return (LdapContext) dirContext.lookup(getLDAPCfg().getSearchBase());

            } catch (Throwable e) {
                // Do nothing. Allow for errors.
                ServletDebugUtil.trace(this,"failed to get any LDAP directory context",e);

            }
        }
        return null;
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
        ServletDebugUtil.trace(this, "search attribute in LDAP is " + getLDAPCfg().getSearchFilterAttribute());
        if (getLDAPCfg().getSearchFilterAttribute() == null) {
            return LDAPConfigurationUtil.SEARCH_FILTER_ATTRIBUTE_DEFAULT; // default
        } else {
            return getLDAPCfg().getSearchFilterAttribute();
        }
    }

    public JSONObject simpleSearch(LdapContext ctx,
                                   String userID,
                                   Map<String, LDAPConfigurationUtil.AttributeEntry> attributes) throws NamingException {
        if (ctx == null) {
            throw new IllegalStateException("Error: Could not create the LDAP context");
        }

        SearchControls searchControls = new SearchControls();
        if (attributes == null || attributes.isEmpty()) {
            // return everything if nothing is specified.
            searchControls.setReturningAttributes(null);
        } else {
            String[] searchAttributes = attributes.keySet().toArray(new String[]{});
            searchControls.setReturningAttributes(searchAttributes);
        }
        String addFilter = "";
        // For all questions about the filter, refer to https://tools.ietf.org/search/rfc4515
        if(!StringUtils.isTrivial(getLDAPCfg().getAdditionalFilter())){
            addFilter = "(" + getLDAPCfg().getAdditionalFilter() + ")";
        }
        String filter = "(&(" + getSearchFilterAttribute() + "=" + userID + ")" + addFilter + ")";
        String contextName = getLDAPCfg().getContextName();
        if(contextName == null){
            // You could use this with the search base but that gets complicated. We lookup the context
            // using the search base elsewhere so there is nothing usually for this parameter to do
            // in cases where this has to be set, the search base has been found which simplifies this
            // value quite a bit.

            contextName = ""; // MUST be set or the query will fail. This is the default
        }
        DebugUtil.trace(this, "filter = " + filter);
        NamingEnumeration e = ctx.search(contextName, filter, searchControls);
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
        JSONObject json = new JSONObject();
        if (!e.hasMoreElements()) {
            DebugUtil.trace(this, "LDAP SEARCH RESULT IS EMPTY");
        }
        if(attributes.isEmpty()){
          // no attribute specified means return everything
          return doEmptyAttrs(e);
        }

        while (e.hasMoreElements()) {
            SearchResult entry = (SearchResult) e.next();
            Attributes a = entry.getAttributes();
            for (String attribID : attributes.keySet()) {
                Attribute attribute = a.get(attribID);
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
        return json;
    }

    /**
     * In this case, the configuration specified no attributes and this should be interpreted as just getting everything.
     * @param e
     * @return
     */
    private JSONObject doEmptyAttrs(NamingEnumeration e) throws NamingException{
          JSONObject all = new JSONObject();
        while (e.hasMoreElements()) {
            SearchResult entry = (SearchResult) e.next();
            Attributes attributes = entry.getAttributes();
            NamingEnumeration aNE = attributes.getAll();
            while(aNE.hasMoreElements()){
               Attribute attribute = (Attribute) aNE.next();
               JSONArray array = new JSONArray();
               for(int i = 0; i < attribute.size(); i++){
                   array.add(attribute.get(i));
               }
               all.put(attribute.getID(), array);
            }

        }
        return all;
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


    public static Groups get_NEW_Gid(LDAPConfiguration cfg2, String username) throws Throwable {
        LDAPConfiguration cfg = cfg2.clone();
        cfg.setSearchBase("ou=Groups,dc=ncsa,dc=illinois,dc=edu");
        // ServletDebugUtil.trace(LDAPClaimsSource.class, "LDAP search is: " + cfg.getSearchFilterAttribute() + "=" + username);
        LDAPClaimsSource claimsSource = new LDAPClaimsSource(cfg, null);
        StringTokenizer stringTokenizer = new StringTokenizer(cfg.getServer(), ",");
        DirContext dirContext = null;
        while (stringTokenizer.hasMoreTokens()) {
            try {
                dirContext = new InitialDirContext(claimsSource.createEnv(stringTokenizer.nextToken(), cfg));
            }catch(Throwable t){
                // go until one works. If we have run out of tokens, then throw the exception.
                 if(!stringTokenizer.hasMoreTokens()){
                     throw t;
                 }
            }
        }
        LdapContext ctx = (LdapContext) dirContext.lookup(cfg.getSearchBase());
        SearchControls searchControls = new SearchControls();
        searchControls.setReturningAttributes(new String[]{"cn", "gidNumber"});
        String filter = "(&(uniqueMember=" + cfg.getSearchFilterAttribute() + "=" + username + ",ou=People,dc=ncsa,dc=illinois,dc=edu))";
        // ServletDebugUtil.trace(LDAPClaimsSource.class, "LDAP filter=" + filter);

        NamingEnumeration e = ctx.search(cfg.getContextName(), filter, searchControls);
        Groups groups = new Groups();
        // ServletDebugUtil.trace(LDAPClaimsSource.class, "Starting to process groups. Has elements? " + e.hasMoreElements() );

        while (e.hasMoreElements()) {
            SearchResult entry = (SearchResult) e.next();
            Attributes a = entry.getAttributes();
            GroupElement groupElement = convertToEntry(a);
            //   ServletDebugUtil.trace(LDAPClaimsSource.class, "Added group element = " + groupElement);

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

}
