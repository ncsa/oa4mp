package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientStoreCommands;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;

import java.net.URI;
import java.util.Collection;
import java.util.LinkedList;
import java.util.StringTokenizer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  3:24 PM
 */
public class OA2ClientCommands extends ClientStoreCommands {
    public OA2ClientCommands(MyLoggingFacade logger,
                             String defaultIndent,
                             Store clientStore,
                             ClientApprovalStore clientApprovalStore) {
        super(logger, defaultIndent, clientStore, clientApprovalStore);
    }

    public boolean isRefreshTokensEnabled() {
        return refreshTokensEnabled;
    }

    public void setRefreshTokensEnabled(boolean refreshTokensEnabled) {
        this.refreshTokensEnabled = refreshTokensEnabled;
    }

    boolean refreshTokensEnabled;

    public Collection<String> getSupportedScopes() {
        return supportedScopes;
    }

    public void setSupportedScopes(Collection<String> supportedScopes) {
        this.supportedScopes = supportedScopes;
    }

    Collection<String> supportedScopes = null;
    @Override
    protected void longFormat(Identifiable identifiable) {
        OA2Client client = (OA2Client) identifiable;
        say("Client name=" + (client.getName() == null ? "(no name)" : client.getName()));
        sayi("identifier=" + client.getIdentifier());
        sayi("email=" + client.getEmail());
        sayi("home uri=" + client.getHomeUri());
        sayi("error uri=" + client.getErrorUri());
        sayi("limited proxies? " + client.isProxyLimited());
        sayi("creation timestamp=" + client.getCreationTS());
        sayi("sign ID tokens?=" + client.isSignTokens());
        sayi("issuer=" + client.getIssuer());
        sayi("is public?=" + client.isPublicClient());
        if (getClientApprovalStore() != null) {
            ClientApproval clientApproval  = null;
            try {
                clientApproval = (ClientApproval) getClientApprovalStore().get(client.getIdentifier());
            }catch(Throwable t){
                // do nothing. If there is no approval record, this is equivalent to saying it is not approved.
            }
            if (clientApproval == null) {
           //     sayi("no approval record exists.");
                sayi("not approved");

            } else {
                if (clientApproval.isApproved()) {
                    String approver = "(unknown)";
                    if (clientApproval.getApprover() != null) {
                        approver = clientApproval.getApprover();
                    }
                    sayi("approved by " + approver);
                } else {
                    sayi("not approved");
                }
            }
        }

        if (client.getSecret() == null) {
            sayi("client secret: (none)");

        } else {
            sayi("client secret (hash):" + client.getSecret());
        }
        Collection<String> uris = client.getCallbackURIs();
        if (uris == null) {
            sayi("callback uris: (none)");
        } else {
            sayi("callback uris" + (uris.isEmpty() ? ":(none)" : ":"));
            for (String x : uris) {
                sayi("      " + x);
            }
        }
        Collection<String> scopes = client.getScopes();
        if(scopes == null){
            sayi("scopes: (none)");
        }else{
            sayi("scopes" + (scopes.isEmpty() ? ":(none)" : ":"));
            for (String x : scopes) {
                sayi("      " + x);
            }
        }
        if (isRefreshTokensEnabled()) {
            sayi("refresh lifetime (sec): " + (client.isRTLifetimeEnabled() ? (client.getRtLifetime() / 1000) : "none"));
        }
        if(client.getLdaps()== null || client.getLdaps().isEmpty()){
            sayi("ldap:(none configured.)");
        }else{
           sayi("LDAPS:" );
            LDAPConfigurationUtil.toJSON(client.getLdaps());
        }
    }

    /**
     * In this case, the secret has to be gotten and processed into a hash,
     * callback uris listed and the refresh token lifetime set.
     * Do not call super on this method since the standard client tracks a public key file rather
     * than the hash of a secret string.
     *
     * @param identifiable
     */
    @Override
    public void extraUpdates(Identifiable identifiable) {
        OA2Client client = (OA2Client) identifiable;
        String secret = client.getSecret();
        String input;
        boolean askForSecret = true;


        while (askForSecret) {
            input = getInput("enter a new secret or return to skip.", secret);
            if (isEmpty(input)) {
                sayi("Nothing entered. Client secret entry skipped.");
                break;
            }
            if (input.equals(secret)) {
                sayi(" Client secret entry skipped.");
                break;
            }
            // input is not empty.
            secret = DigestUtils.sha1Hex(input);
            client.setSecret(secret);
            askForSecret = false;
        }
        OA2Client oa2Client = (OA2Client) identifiable;
        if (isRefreshTokensEnabled()) {
            // so at this point the server actually allows for refresh tokens
            String NONE = "none";
            String rtString = oa2Client.isRTLifetimeEnabled()?Long.toString(oa2Client.getRtLifetime()/1000) : NONE;
            String rawLifetime = getInput("enter the refresh lifetime in ms.", rtString);

            if (rawLifetime == null || rawLifetime.length() == 0 || rawLifetime.toLowerCase().equals(NONE)) {
                oa2Client.setRtLifetime(0);
            } else {
                try {
                    oa2Client.setRtLifetime(Long.parseLong(rawLifetime));
                } catch (Throwable t) {
                    sayi("Sorry but \"" + rawLifetime + "\" is not a valid number. No change.");
                }
            }
        }
        boolean publicClient = oa2Client.isPublicClient();
        String rawPC = getInput("is this client public?", Boolean.toString(publicClient));
        if(rawPC != null && rawPC.toLowerCase().equalsIgnoreCase("y") || rawPC.toLowerCase().equalsIgnoreCase("yes")){
            rawPC = "true";
        }
        try{
            boolean x = Boolean.parseBoolean(rawPC);
            oa2Client.setPublicClient(x);
        }catch(Throwable t){
            sayi("Sorry, but unable to parse the response of \"" + rawPC +  "\". No change.");
        }

        String issuer = getInput("enter the issuer (optional)", oa2Client.getIssuer());
        if(!isEmpty(issuer)){
            oa2Client.setIssuer(issuer);
        }

        String signTokens = getInput("Enable ID token signing (true/false)?", Boolean.toString(oa2Client.isSignTokens()));
        if(!isEmpty(signTokens)){
            try{
                oa2Client.setSignTokens(Boolean.parseBoolean(signTokens));
            }catch(Throwable t){
                // do nothing.
                sayi("Unknown response of \"" + signTokens + "\". Must be \"true\" or \"false\", ignoring.");
            }
        }

        String currentScopes = null;
        if(oa2Client.getScopes() != null){
            boolean firstPass = true;
            for (String x : oa2Client.getScopes()) {
                if (firstPass) {
                    firstPass = false;
                    currentScopes = x;
                } else {
                    currentScopes = currentScopes+ "," + x;
                }
            }
        }
        String scopes = getInput("enter a comma separated list of scopes. Scopes to this server will be rejected.", currentScopes);

        if (!(scopes==null || scopes.isEmpty())) {
            LinkedList<String> list = new LinkedList<>();
            StringTokenizer stringTokenizer = new StringTokenizer(scopes, ",");
            while (stringTokenizer.hasMoreTokens()) {
                String raw = stringTokenizer.nextToken().trim();
                if(getSupportedScopes().contains(raw)){
                    list.add(raw);
                }else{
                    say("Unknown scope \"" + raw + "\" rejected.");
                }
            }
            oa2Client.setScopes(list);
        }

        // Now do much the same for the list of callback URIs
        String currentUris = null;
        if (oa2Client.getCallbackURIs() != null) {
            boolean firstPass = true;
            for (String x : oa2Client.getCallbackURIs()) {
                if (firstPass) {
                    firstPass = false;
                    currentUris = x;
                } else {
                    currentUris = currentUris + "," + x;
                }
            }
        }
        String uris = getInput("enter a comma separated list of callback uris. These must start with https or they will be ignored.", currentUris);

        if (!uris.isEmpty()) {
            LinkedList<String> list = new LinkedList<>();
            StringTokenizer stringTokenizer = new StringTokenizer(uris, ",");
            while (stringTokenizer.hasMoreTokens()) {
                String raw = stringTokenizer.nextToken().trim();
                try {
                    URI uri = URI.create(raw);
                    if (uri.getScheme().toLowerCase().equals("https")) {
                        list.add(raw);
                    }else{
                        sayi("\"" + raw+ "\" rejected -- illegal protocol");
                    }
                }catch(Throwable t){
                    // do nothing. Just ignore illegal uris.
                    sayi("\"" + raw+ "\" rejected -- illegal uri");
                }
            }
            oa2Client.setCallbackURIs(list);
        }
        String currentLDAPs = null;
        if(client.getLdaps() == null || client.getLdaps().isEmpty()){
         currentLDAPs = "";
        }   else{
            currentLDAPs = LDAPConfigurationUtil.toJSON(client.getLdaps()).toString();
        }
      String ldaps = getInput("Enter a valid JSON object or array for the ldap configuration(s).", currentLDAPs);
        if(!ldaps.isEmpty()){
            // try to parse it as a single LDAP entry
            JSON json = null;
            try{
                JSONArray array = JSONArray.fromObject(ldaps);
                json = array;
            }catch(Throwable t){
                // ok, so that is not an array, try a singleton
                try {
                    JSONObject jsonObject = JSONObject.fromObject(ldaps);
                    json = jsonObject;
                }catch(Throwable tt){
                    sayi("Sorry, could not parse JSON");
                }
             if(json != null){
                 client.setLdaps(LDAPConfigurationUtil.fromJSON(json));
             }
            }
        }

    }

    public OA2ClientCommands(MyLoggingFacade logger, Store store) {
        super(logger, store);
    }
}
