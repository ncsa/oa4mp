package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.NewClientEvent;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.NewClientNotifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.util.mail.MailUtil;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/12/17 at  2:06 PM
 */
public class OA2NewClientNotifier extends NewClientNotifier {
    public static final String SCOPES = "scopes";
    public static final String REFRESH_LIFETIME = "refreshLifetime";
    public static final String REFRESH_ENABLED = "refreshEnabled";
    public static final String ISSUER = "issuer";
    public static final String SIGN_TOKEN_OK = "signTokens";
    public static final String LDAP_CONFIGURATION = "ldapConfiguration";
    public static final String CALLBACK = "callback";
    public static final String IS_PUBLIC = "isPublic";
    public static final String STRICT_SCOPES = "strictScopes";


    public OA2NewClientNotifier(MailUtil mailUtil, MyLoggingFacade loggingFacade) {
        super(mailUtil, loggingFacade);
    }

    @Override
    protected Map<String, String> getReplacements(BaseClient client) {
        Map<String, String> replacements = super.getReplacements(client);
        if (client instanceof AdminClient) {
            // Unfortunately, since the servlet has a single new client notifier we have to check
            // for the instance here and not do anything unless its an OA2Client
            return replacements;
        }
        OA2Client oa2Client = (OA2Client) client;
        replacements.remove(FAILURE_URI); // don't need for OA2 clients.
        replacements.put(SCOPES, String.valueOf(oa2Client.getScopes()));
        replacements.put(CALLBACK, String.valueOf(oa2Client.getCallbackURIs()));
        replacements.put(REFRESH_ENABLED, Boolean.toString(oa2Client.isRTLifetimeEnabled()));
        replacements.put(IS_PUBLIC, Boolean.toString(oa2Client.isPublicClient()));
        replacements.put(STRICT_SCOPES, Boolean.toString(oa2Client.useStrictScopes()));
        if (oa2Client.isRTLifetimeEnabled()) {
            replacements.put(REFRESH_LIFETIME, Long.toString(oa2Client.getRtLifetime()));
        } else {
            replacements.put(REFRESH_LIFETIME, "n/a");
        }
        replacements.put(SIGN_TOKEN_OK, Boolean.toString(oa2Client.isSignTokens()));
        if (oa2Client.getLdaps() == null || oa2Client.getLdaps().isEmpty()) {
            replacements.put(LDAP_CONFIGURATION, "(none)");

        } else {
            LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();
            replacements.put(LDAP_CONFIGURATION, ldapConfigurationUtil.toJSON(oa2Client.getLdaps()).toString(2));
        }
        if (oa2Client.getIssuer() == null) {
            replacements.put(ISSUER, "(none)");
        } else {
            replacements.put(ISSUER, oa2Client.getIssuer());
        }
        return replacements;
    }

    @Override
    public void fireNewClientEvent(NewClientEvent notificationEvent) {
        if (!mailUtil.isEnabled()) {
            return;
        }
        BaseClient client = notificationEvent.getClient();
        Map<String, String> replacements = getReplacements(client);

        boolean rc = false;
        if (client instanceof AdminClient) {
            String subject = "New administrative client registration on ${host}";
            String body = "A new administrative client has requested approved on ${host}\n\n"
                    + "If you approve this request, you should send a notice\n" +
                    "to the contact email and include the generated identifier.\n" +
                    "Please review all of the information below prior to approval.\n\n" +
                    "Generated identifier: ${identifier}\n" +
                    "Creation time: ${creationTime}\n" +
                    "\n" +
                    "Name: ${name}\n" +
                    "Contact email: ${email}";
            rc = mailUtil.sendMessage(subject, body, replacements);

        } else {
            rc = mailUtil.sendMessage(replacements);

        }
        if (rc) {
            loggingFacade.info("sending email notification for client " + client.getIdentifierString());
        } else {
            loggingFacade.info("failure sending email notification for client " + client.getIdentifierString());
        }

    }

}
