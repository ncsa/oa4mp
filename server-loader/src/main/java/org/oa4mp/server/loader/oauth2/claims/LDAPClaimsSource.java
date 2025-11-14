package org.oa4mp.server.loader.oauth2.claims;

import edu.uiuc.ncsa.security.core.Logable;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.server.UnsupportedScopeException;
import org.oa4mp.delegation.server.server.claims.ClaimSourceConfiguration;
import org.oa4mp.delegation.server.server.config.LDAPConfiguration;
import org.oa4mp.delegation.server.server.config.LDAPConfigurationUtil;
import org.oa4mp.server.api.storage.servlet.OA4MPServlet;
import org.oa4mp.server.api.util.ExceptionEvent;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.servlet.GroupHandler;
import org.oa4mp.server.loader.oauth2.servlet.NCSAGroupHandler;
import org.qdl_lang.variables.QDLStem;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.LdapContext;
import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.*;

import static org.oa4mp.server.loader.qdl.claims.CSConstants.*;
import static org.qdl_lang.variables.StemUtility.put;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/26/16 at  3:32 PM
 */
public class LDAPClaimsSource extends BasicClaimsSourceImpl implements Logable {

    private static final long serialVersionUID = 7590118446767325062L;

    public LDAPClaimsSource() {
    }

    public LDAPClaimsSource(QDLStem stem) {
        super(stem);
    }

    public LDAPClaimsSource(QDLStem stem, OA2SE oa2SE) {
        super(stem, oa2SE);
    }

    public LDAPClaimsSource(LDAPConfiguration ldapConfiguration, MyLoggingFacade myLogger) {
        super();
        if (ldapConfiguration == null) {
            throw new LDAPException("null ldap config");
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
            throw new LDAPException("null service env");
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
        String dbgname = ".getSearchName(id=" + getLDAPCfg().getId() + ", search name key=" + getLDAPCfg().getSearchNameKey() + ")";

        DebugUtil.trace(this, dbgname);
        LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();
        JSONObject xxx = ldapConfigurationUtil.toJSON(getLDAPCfg());
        if (xxx.getJSONObject("ldap").containsKey("ssl")) {
            xxx.getJSONObject("ldap").getJSONObject("ssl").put("keystore", "");
        }
        if (getLDAPCfg().getSearchNameKey() == null) {
            warn(dbgname + "No search name given for LDAP query. Using default of username");
            return transaction.getUsername();
        }
        if (getLDAPCfg().getSearchNameKey().equals(LDAPConfigurationUtil.SEARCH_NAME_USERNAME)) {
            DebugUtil.trace(this, dbgname + " searching using the username");
            return transaction.getUsername();
        }
        if (!claims.containsKey(getLDAPCfg().getSearchNameKey()) || claims.get(getLDAPCfg().getSearchNameKey()) == null) {
            String message = "no recognized search name key was found in the claims for config with id=" + getLDAPCfg().getId() +
                    ". Requested was \"" + getLDAPCfg().getSearchNameKey() + "\"";
            DebugUtil.trace(this, message);
            throw new LDAPException(message);
        }
        String searchName = (String) claims.get(getLDAPCfg().getSearchNameKey());
        if (searchName == null || searchName.isEmpty()) {
            // If the configuration file has an error, this will be the one place it shows first.
            // Best to trap it here and fail rather than have LDAP do the query (which it will and
            // return nothing) and inexplicably have no result.
            throw new LDAPException("No search name found for LDAP query.");
        }
        DebugUtil.trace(this, ".getSearchName(id=" + getLDAPCfg().getId() + ", returning " + searchName );

        return searchName;
    }

    protected boolean isNCSA() {
        ServletDebugUtil.trace(this, "checking if is NCSA LDAP claims source for \"" + currentServerAddress + "\"");
        return currentServerAddress.endsWith(".ncsa.illinois.edu");
    }

    transient MyLoggingFacade myLogger = null;

    protected MyLoggingFacade getMyLogger() {
        return myLogger;
    }

    /*   All NamingException subclasses for reference:

     AttributeInUseException,
     AttributeModificationException,
     CannotProceedException,
     CommunicationException,
     ConfigurationException,
     ContextNotEmptyException,
     InsufficientResourcesException,
     InterruptedNamingException,
     InvalidAttributeIdentifierException,
     InvalidAttributesException,
     InvalidAttributeValueException,
     InvalidNameException,
     InvalidSearchControlsException,
     InvalidSearchFilterException,
     LimitExceededException,
     LinkException,
     NameAlreadyBoundException,
     NameNotFoundException,
     NamingSecurityException,
     NoInitialContextException,
     NoSuchAttributeException,
     NotContextException,
     OperationNotSupportedException,
     PartialResultException,
     ReferralException,
     SchemaViolationException,
     ServiceUnavailableException
 */
    public void handleException(Throwable throwable, MetaDebugUtil debugger) {
debugger.trace(this, "LDAP error (" + throwable.getClass().getSimpleName() + "):" + throwable.getMessage());
throwable.printStackTrace();
        if (throwable instanceof NamingException) {
            // Fix for https://jira.ncsa.illinois.edu/browse/CIL-1943
            String msg = throwable.getClass().getSimpleName() + " talking to LDAP:" + throwable.getMessage();
            debugger.warn(this, msg);
            // Fix https://github.com/ncsa/oa4mp/issues/246
            if (getConfiguration().isNotifyOnFail()) {
                warn(msg);
            }
            if (getConfiguration().isFailOnError()) {
                throw new LDAPException(msg, throwable);
            }
            return;
        }
        debugger.error(this, "Error accessing LDAP", throwable);
        if (getLDAPCfg().isFailOnError()) {
            String message = (throwable instanceof NullPointerException) ? "(null pointer)" : throwable.getMessage();
            if (getMyLogger() != null) {
                getMyLogger().warn("Could not get LDAP information:" + message);
            }
            if (getLDAPCfg().isNotifyOnFail()) {
                String subjectTemplate = "Error on ${host} contacting LDAP server";
                String messageTemplate = "The following error message was received attempting to contact the " +
                        "LDAP server at ${ldap_host}:\n\n${message}\n\n. The operation did not complete.";
                Map<String, String> replacements = new HashMap<>();
                String x = "localhost";
                if (getOa2SE() != null) {
                    URI address = getOa2SE().getServiceAddress();
                    if (address != null) {
                        x = address.getHost();
                    }
                    replacements.put("host", x);
                    replacements.put("ldap_host", getLDAPCfg().getServer());
                    replacements.put("message", throwable.getMessage());
                    ExceptionEvent exceptionEvent = new ExceptionEvent(this, throwable, replacements);
                    getOa2SE().getMailUtil().sendMessage(exceptionEvent, subjectTemplate, messageTemplate, replacements);
                }
            }

            throw new LDAPException("Could not communicate with LDAP server: \"" + (throwable.getMessage() == null ? "(no message)" : throwable.getMessage()) + "\"");
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
        String name = "realProcessing(id=" + getLDAPCfg().getId() + "):";
        MetaDebugUtil debugger = OA4MPServlet.createDebugger(transaction.getClient());

        debugger.trace(this, name + " preparing to do processing, cfg:\n" + getLDAPCfg().toJSON().toString(1));
        debugger.trace(this, name + " initial claims:\n" + claims.toString(1));

        if (!isEnabled()) {
            debugger.trace(this, name + " Claims source not enabled.");
            return claims;
        }

        if (!isLoggedOn()) {
            logon(debugger);
            if(!isLoggedOn() && !getLDAPCfg().isFailOnError()){
                debugger.trace(this, name + " logon FAILED!");
                return claims;
            }
        }
        try {
            String searchName = getSearchName(claims, request, transaction);
            debugger.trace(this, name + " search name=\"" + searchName+"\"");

            if (searchName != null) {
                Map tempMap = simpleSearch(context, searchName, getLDAPCfg().getSearchAttributes(), debugger);
                claims.putAll(tempMap);
            } else {
                info("No search name encountered for LDAP query. No search performed.");
            }
            context.close();
        } catch (Throwable throwable) {
            debugger.trace(this, name + " Error getting search name \"" + throwable.getMessage() + "\"", throwable);
            handleException(throwable, debugger);
        } finally {
            closeConnection();
        }
        debugger.trace(this, name + " claims=" + claims);

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


    public void logon(MetaDebugUtil debugUtil) {
        context = createConnection(debugUtil);
    }

    public Hashtable<String, String> createEnv(String host, LDAPConfiguration cfg) {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        String providerUrl = host.trim();
        if (!host.startsWith("ldaps://")) {
            providerUrl = "ldaps://" + providerUrl;
        }
        if (0 <= cfg.getPort()) {
            providerUrl = providerUrl + ":" + cfg.getPort();
        }
        env.put(Context.PROVIDER_URL, providerUrl);
        env.put("com.sun.jndi.ldap.read.timeout", "10000"); // time is in ms.

        /*
        Great. For OpenJDK java 8  this is broken over SSL:
        https://bugs.openjdk.java.net/browse/JDK-8173451
         */

        switch (cfg.getAuthType()) {
            case LDAPConfigurationUtil.LDAP_AUTH_NONE_KEY:
                env.put(Context.SECURITY_AUTHENTICATION, LDAPConfigurationUtil.LDAP_AUTH_NONE);
                env.put(Context.SECURITY_PROTOCOL, "ssl");

                break;
            case LDAPConfigurationUtil.LDAP_AUTH_SIMPLE_KEY:
                env.put(Context.SECURITY_AUTHENTICATION, LDAPConfigurationUtil.LDAP_AUTH_SIMPLE);
                env.put(Context.SECURITY_PRINCIPAL, cfg.getSecurityPrincipal());
                env.put(Context.SECURITY_CREDENTIALS, cfg.getPassword());
                env.put("javax.security.sasl.server.authentication", "true");

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

    public LdapContext createConnection(MetaDebugUtil debugger) {
        // Set up the environment for creating the initial context
        StringTokenizer stringTokenizer = new StringTokenizer(getLDAPCfg().getServer(), ",");

        DirContext dirContext = null;
        // Fix https://github.com/ncsa/oa4mp/issues/113
        int retryCount = Math.max(1, getLDAPCfg().getRetryCount()); // make sure it trips once
        Throwable lastException = null;
        for (int i = 0; i < retryCount; i++) {
            while (stringTokenizer.hasMoreTokens()) {
                try {
                    currentServerAddress = stringTokenizer.nextToken().trim(); // chop out extra blanks!
                    dirContext = new InitialDirContext(createEnv(currentServerAddress, getLDAPCfg()));
                    debugger.trace(this, "Found LDAP server for address=\"" + currentServerAddress + "\"");
                    return (LdapContext) dirContext.lookup(getLDAPCfg().getSearchBase());
                } catch (Throwable e) {
                    // Do nothing. Allow for errors until very end.
                    String msg = e.getClass().getSimpleName() + " failure for LDAP server # " + i + ": " + e.getMessage();
                    debugger.trace(this, msg, e);
                    lastException = e;
                }
            }
            if (0 < getLDAPCfg().getMaxWait()) {
                try {
                    Thread.currentThread().sleep(getLDAPCfg().getMaxWait());
                } catch (InterruptedException e) {
                    if (DebugUtil.isEnabled()) {
                        e.printStackTrace();
                    }
                    info("sleep in " + getClass().getSimpleName() + " + interrupted:" + e.getMessage());
                }
            }
        }
        // Fix https://github.com/ncsa/oa4mp/issues/246 let handleException do the work so it's centralized
        handleException(lastException, debugger); // failed the max number of times, so handle the error.
        // Note that the previous line will rnd up throwing the correct exception, so the next
        // line never should execute. It must be here though or Java won't compile.
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
    protected String getSearchFilterAttribute(MetaDebugUtil debugger) {
        debugger.trace(this, "search attribute in LDAP is " + getLDAPCfg().getSearchFilterAttribute());
        if (getLDAPCfg().getSearchFilterAttribute() == null) {
            return LDAPConfigurationUtil.SEARCH_FILTER_ATTRIBUTE_DEFAULT; // default
        } else {
            return getLDAPCfg().getSearchFilterAttribute();
        }
    }

    public JSONObject simpleSearch(LdapContext ctx,
                                   String userID,
                                   Map<String, LDAPConfigurationUtil.AttributeEntry> attributes,
                                   MetaDebugUtil debugger) throws NamingException {
        if (ctx == null) {
            // CIL-1306: This is a little tricky. An LDAP configuration can have several alternate
            // hosts to try, so failures are expected and considered benign. Only if the very last one
            // fails is it considered a failure. This tries to construct a more helpful message.
            throw new LDAPException("could not create the LDAP context on " + (new Date()) +
                    " server=" + getLDAPCfg().getServer() + ", base=" + getLDAPCfg().getSearchBase());
        }

        SearchControls searchControls = new SearchControls();
        if (attributes == null || attributes.isEmpty()) {
            // return everything if nothing is specified.
            searchControls.setReturningAttributes(null);
        } else {
            String[] searchAttributes = attributes.keySet().toArray(new String[]{});
            searchControls.setReturningAttributes(searchAttributes);
        }
        // CIL-1553 = add search scope
        if (getLDAPCfg().hasSearchScope()) {

            switch (getLDAPCfg().getSearchScope()) {
                case LDAPConfigurationUtil.SEARCH_SCOPE_OBJECT:
                    searchControls.setSearchScope(SearchControls.OBJECT_SCOPE);
                    break;
                case LDAPConfigurationUtil.SEARCH_SCOPE_ONE_LEVEL:
                    searchControls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
                    break;
                case LDAPConfigurationUtil.SEARCH_SCOPE_SUBTREE:
                    searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                    break;
                default:
                    throw new IllegalArgumentException("unknown search scope \"" + getLDAPCfg().getSearchScope() + "\"");
            }
        }
        //String addFilter = "";
        // For all questions about the filter, refer to https://tools.ietf.org/search/rfc4515
        String filter;
        // CIL-1296. the filter attribute should replace the simple default constructed filter.
        if (!StringUtils.isTrivial(getLDAPCfg().getAdditionalFilter())) {
            // If they specify it, use the whole thing.
            //filter = "(" + getLDAPCfg().getAdditionalFilter() + ")";
            filter = getLDAPCfg().getAdditionalFilter();
        } else {
            // if the filter is not specified,, try to construct it.
            filter = "(" + getSearchFilterAttribute(debugger) + "=" + userID + ")";
        }
        String contextName = getLDAPCfg().getContextName();
        if (contextName == null) {
            // You could use this with the search base but that gets complicated. We lookup the context
            // using the search base elsewhere so there is nothing usually for this parameter to do
            // in cases where this has to be set, the search base has been found which simplifies this
            // value quite a bit.

            contextName = ""; // MUST be set or the query will fail. This is the default
        }
        debugger.trace(this, "filter = " + filter);
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
        if (attributes.isEmpty()) {
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
     *
     * @param e
     * @return
     */
    private JSONObject doEmptyAttrs(NamingEnumeration e) throws NamingException {
        JSONObject all = new JSONObject();
        while (e.hasMoreElements()) {
            SearchResult entry = (SearchResult) e.next();
            Attributes attributes = entry.getAttributes();
            NamingEnumeration aNE = attributes.getAll();
            while (aNE.hasMoreElements()) {
                Attribute attribute = (Attribute) aNE.next();
                JSONArray array = new JSONArray();
                for (int i = 0; i < attribute.size(); i++) {
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
            } catch (Throwable t) {
                // go until one works. If we have run out of tokens, then throw the exception.
                if (!stringTokenizer.hasMoreTokens()) {
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
            throw new NFWException("The group name somehow was empty. This implies the LDAP entry has changed or is incorrect");
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

    @Override
    public void fromQDL(QDLStem arg) {
        DebugUtil.trace(this, "fromQDL:\n" + arg.toString(1));
        LDAPConfiguration ldapCfg = new LDAPConfiguration();
        setConfiguration(ldapCfg);
        super.fromQDL(arg);
        LDAPConfigurationUtil cUtil = new LDAPConfigurationUtil();
        ldapCfg.setSearchNameKey(arg.getString(CS_LDAP_SEARCH_NAME));
        ldapCfg.setServer(arg.getString(CS_LDAP_SERVER_ADDRESS));
        if (arg.containsKey(CS_LDAP_SEARCH_FILTER_ATTRIBUTE)) {
            ldapCfg.setSearchFilterAttribute(arg.getString(CS_LDAP_SEARCH_FILTER_ATTRIBUTE));
        }
        if (arg.containsKey(CS_LDAP_SEARCH_SCOPE)) {
            ldapCfg.setSearchScope(arg.getString(CS_LDAP_SEARCH_SCOPE));
        }


        if (arg.containsKey(CS_DEFAULT_IS_ENABLED)) {
            ldapCfg.setEnabled(arg.getBoolean(CS_DEFAULT_IS_ENABLED));
        } else {
            ldapCfg.setEnabled(true);
        }
        if (arg.containsKey(CS_LDAP_ADDITIONAL_FILTER)) {
            ldapCfg.setAdditionalFilter(arg.getString(CS_LDAP_ADDITIONAL_FILTER));
        } else {
            ldapCfg.setAdditionalFilter("");
        }
        if (arg.containsKey(CS_LDAP_CONTEXT_NAME)) {
            ldapCfg.setContextName(arg.getString(CS_LDAP_CONTEXT_NAME));
        } else {
            ldapCfg.setContextName("");// default. MUST be present of the search internally throws an NPE...
        }
        if (arg.containsKey(CS_LDAP_PORT)) {
            ldapCfg.setPort(arg.getLong(CS_LDAP_PORT).intValue());
        } else {
            ldapCfg.setPort(LDAPConfigurationUtil.DEFAULT_PORT);
        }

        ldapCfg.setAuthType(cUtil.getAuthType(arg.getString(CS_LDAP_AUTHZ_TYPE)));
        if (ldapCfg.getAuthType() == LDAPConfigurationUtil.LDAP_AUTH_SIMPLE_KEY) {
            ldapCfg.setPassword(arg.getString(CS_LDAP_PASSWORD));
            ldapCfg.setSecurityPrincipal(arg.getString(CS_LDAP_SECURITY_PRINCIPAL));
        }
        ldapCfg.setSearchBase(arg.getString(CS_LDAP_SEARCH_BASE));
        // now to construct the search attributes.
/*                    Example. Have to specify search_attributes explicitly or no rename possible
                  Omitting search_attributes means to get them all.
           {
             'auth_type':'simple',
             'password':'XXXX',
             'address':'ldap.cilogon.org',
             'port':636,
             'rename':{'sn':'title'},
             'claim_name':'uid',
             'search_base':'ou=people,o=Fermilab,o=CO,dc=cilogon,dc=org',
             'search_attributes':['isMemberOf','sn','cn','voPersonID'],
             'rename' :{'isMemberOf':'is_member_of'},
             'type':'ldap',
             'ldap_name':'voPersonExternalID',
             'username':'uid=oa4mp_user,ou=system,o=Fermilab,o=CO,dc=cilogon,dc=org'
           }
             */
        QDLStem renames = null;
        if (arg.containsKey(CS_LDAP_RENAME)) {
            renames = arg.get(CS_LDAP_RENAME).asStem();
        }
        Collection lists = null;
        if (arg.containsKey(CS_LDAP_LISTS)) {
            QDLStem listNames = arg.get(CS_LDAP_LISTS).asStem();
            lists = listNames.values();
        } else {
            lists = new ArrayList();
        }

        Collection groups;
        if (arg.containsKey(CS_LDAP_GROUP_NAMES)) {
            QDLStem groupStem = arg.get(CS_LDAP_GROUP_NAMES).asStem();
            groups = groupStem.values();
        } else {
            groups = new ArrayList();
        }

        if (arg.containsKey(CS_LDAP_SEARCH_ATTRIBUTES)) {
            // no attribute means they are getting everything. Let them.
            QDLStem searchAttr = arg.get(CS_LDAP_SEARCH_ATTRIBUTES).asStem();
            Map<String, LDAPConfigurationUtil.AttributeEntry> attrs = new HashMap<>();

            for (Object key : searchAttr.keySet()) {
                String attrName = String.valueOf(searchAttr.get(key));
                boolean isGroup = groups.contains(attrName);
                boolean isList = lists.contains(attrName);
                if (isList && isGroup) {
                    throw new IllegalArgumentException("You cannot have a \"" + attrName + "\" be both a group and a list. ");
                }
                String rename = attrName;
                if (renames != null) {
                    if (renames.containsKey(attrName)) {
                        rename = renames.getString(attrName);
                    }
                }
                LDAPConfigurationUtil.AttributeEntry attributeEntry =
                        new LDAPConfigurationUtil.AttributeEntry(attrName, rename, isList, isGroup);
                attrs.put(attrName, attributeEntry);
            }
            if (!attrs.isEmpty()) {
                ldapCfg.setSearchAttributes(attrs);
            }
        }

    }

    @Override
    public QDLStem toQDL() {
        QDLStem stem = super.toQDL();
        LDAPConfigurationUtil cUtil = new LDAPConfigurationUtil();
        LDAPConfiguration cfg2 = (LDAPConfiguration) getConfiguration();
        addToStem(stem, CS_DEFAULT_TYPE, CS_TYPE_LDAP);
        addToStem(stem, CS_LDAP_SEARCH_NAME, cfg2.getSearchNameKey());
        addToStem(stem, CS_LDAP_SERVER_ADDRESS, cfg2.getServer());
        addToStem(stem, CS_LDAP_SEARCH_BASE, cfg2.getSearchBase()); // Fixes CIL-1328
        addToStem(stem, CS_LDAP_CONTEXT_NAME, cfg2.getContextName());
        addToStem(stem, CS_LDAP_ADDITIONAL_FILTER, cfg2.getAdditionalFilter());
        addToStem(stem, CS_LDAP_PORT, new Long(cfg2.getPort()));
        addToStem(stem, CS_LDAP_AUTHZ_TYPE, cUtil.getAuthName(cfg2.getAuthType()));
        addToStem(stem, CS_LDAP_SEARCH_FILTER_ATTRIBUTE, cfg2.getSearchFilterAttribute());
        if (cfg2.hasSearchScope()) {
            put(stem, CS_LDAP_SEARCH_SCOPE, cfg2.getSearchScope());
        }

        if (cfg2.getAuthType() == LDAPConfigurationUtil.LDAP_AUTH_SIMPLE_KEY) {
            put(stem, CS_LDAP_PASSWORD, cfg2.getPassword());
            put(stem, CS_LDAP_SECURITY_PRINCIPAL, cfg2.getSecurityPrincipal());
        }

        if (cfg2.getSearchAttributes() != null && !cfg2.getSearchAttributes().isEmpty()) {
            List<Object> groups = new ArrayList<>();
            List<Object> names = new ArrayList<>();
            List<Object> isList = new ArrayList<>();
            QDLStem renames = new QDLStem();
            for (String key : cfg2.getSearchAttributes().keySet()) {
                LDAPConfigurationUtil.AttributeEntry attributeEntry = cfg2.getSearchAttributes().get(key);
                names.add(attributeEntry.sourceName);
                if (attributeEntry.targetName != null && !attributeEntry.targetName.equals(attributeEntry.sourceName)) {
                    put(renames, attributeEntry.sourceName, attributeEntry.targetName);
                }
                if (attributeEntry.isGroup) {
                    groups.add(attributeEntry.sourceName);
                }
                if (attributeEntry.isList) {
                    isList.add(attributeEntry.sourceName);
                }
                QDLStem nameStem = new QDLStem();
                nameStem.addList(names);
                put(stem, CS_LDAP_SEARCH_ATTRIBUTES, nameStem);

                if (groups.size() != 0) {
                    QDLStem groupStem = new QDLStem();
                    groupStem.addList(groups);
                    put(stem, CS_LDAP_GROUP_NAMES, groupStem);
                }
                if (isList.size() != 0) {
                    QDLStem listStem = new QDLStem();
                    listStem.addList(isList);
                    put(stem, CS_LDAP_LISTS, listStem);
                }
                if (renames.size() != 0) {
                    put(stem, CS_LDAP_RENAME, renames);
                }
            }

        }
        return stem;
    }

    /**
     * Lazy initialization since it is assumed that this is needed to populate this from JSON or QDL.
     *
     * @return
     */
    @Override
    public ClaimSourceConfiguration getConfiguration() {
        if (configuration == null) {
            configuration = new LDAPConfiguration();
        }
        return configuration;
    }

}
