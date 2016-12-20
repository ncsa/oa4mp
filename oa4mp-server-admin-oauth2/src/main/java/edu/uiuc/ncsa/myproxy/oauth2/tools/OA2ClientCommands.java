package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientStoreCommands;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.Collection;
import java.util.LinkedList;
import java.util.StringTokenizer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  3:24 PM
 */
public class OA2ClientCommands extends ClientStoreCommands {
    public OA2ClientCommands(MyLoggingFacade logger, String defaultIndent, Store clientStore, ClientApprovalStore clientApprovalStore) {
        super(logger, defaultIndent, clientStore, clientApprovalStore);
    }

    public boolean isRefreshTokensEnabled() {
        return refreshTokensEnabled;
    }

    public void setRefreshTokensEnabled(boolean refreshTokensEnabled) {
        this.refreshTokensEnabled = refreshTokensEnabled;
    }

    boolean refreshTokensEnabled;

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
        sayi("issuer=" + client.getIssuer());
        if (getClientApprovalStore() != null) {
            ClientApproval clientApproval = (ClientApproval) getClientApprovalStore().get(client.getIdentifier());
            if (clientApproval == null) {
                sayi("no approval record exists.");
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
        if (isRefreshTokensEnabled()) {
            sayi("refresh lifetime (sec): " + (client.isRTLifetimeEnabled() ? (client.getRtLifetime() / 1000) : "none"));
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
            String rawLifetime = getInput("enter the refresh lifetime in ", rtString);

            if (rawLifetime == null || rawLifetime.length() == 0 || rawLifetime.toLowerCase().equals(NONE)) {
                oa2Client.setRtLifetime(Long.MIN_VALUE);
            } else {
                try {
                    oa2Client.setRtLifetime(Long.parseLong(rawLifetime));
                } catch (Throwable t) {
                    sayi("Sorry but \"" + rawLifetime + "\" is not a valid number. No change.");
                }
            }
        }

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
        String uris = getInput("enter a comma separated list of callback uris", currentUris);

        if (!isEmpty(uris)) {
            LinkedList<String> list = new LinkedList<>();
            StringTokenizer stringTokenizer = new StringTokenizer(uris, ",");
            while (stringTokenizer.hasMoreTokens()) {
                list.add(stringTokenizer.nextToken().trim());
            }
            oa2Client.setCallbackURIs(list);
        }

        String issuer = getInput("enter the issuer (optional)", oa2Client.getIssuer());
        if(!(issuer == null || issuer.length() == 0)){
            oa2Client.setIssuer(issuer);
        }
    }

    public OA2ClientCommands(MyLoggingFacade logger, Store store) {
        super(logger, store);
    }
}
