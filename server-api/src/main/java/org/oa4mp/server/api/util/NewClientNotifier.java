package org.oa4mp.server.api.util;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.security.servlet.Notifier;
import edu.uiuc.ncsa.security.util.mail.MailUtil;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/14/12 at  5:38 PM
 */
public class NewClientNotifier extends Notifier implements NewClientListener {

    public static final String NAME = "name";
    public static final String EMAIL = "email";
    public static final String HOME_URI = "homeUri";
    public static final String FAILURE_URI = "failureUri";
    public static final String CREATION_TIME = "creationTime";
    public static final String IDENTIFIER = "identifier";
    public static final String LIMITED_PROXY = "limitedProxy";
    public static final String REPLY_TO = "reply-to";

    public NewClientNotifier(MailUtil mailUtil, MyLoggingFacade loggingFacade) {
        super(mailUtil, loggingFacade);
    }

    protected Map<String,String> getReplacements(BaseClient client) {
        HashMap<String, String> replacements = new HashMap<String, String>();

        replacements.put(NAME, client.getName());
        replacements.put(EMAIL, client.getEmail());
        replacements.put(CREATION_TIME, client.getCreationTS().toString());
        replacements.put(IDENTIFIER, client.getIdentifierString());
        replacements.put(REPLY_TO, client.getEmail());
        // couple of special cases
        if(client instanceof Client){
            Client client2 = (Client)client;
            replacements.put(HOME_URI, client2.getHomeUri());
            replacements.put(FAILURE_URI, client2.getErrorUri());
            replacements.put(LIMITED_PROXY, Boolean.toString(client2.isProxyLimited()));
        }
        try {
            replacements.put("host", InetAddress.getLocalHost().getCanonicalHostName());
        } catch (UnknownHostException e) {
            loggingFacade.warn("Error: Could not resolve localhost, so could not put full name into message");
            replacements.put("host", "localhost");
        }

        return replacements;
    }

    @Override
    public void fireNewClientEvent(NewClientEvent notificationEvent) {
        if (!mailUtil.isEnabled()) {
            return;
        }
        BaseClient client = notificationEvent.getClient();
        Map<String,String> replacements = getReplacements(client);

        boolean rc = mailUtil.sendMessage(replacements);
        if (rc) {
            loggingFacade.info("sending email notification for client " + client.getIdentifierString());
        } else {
            loggingFacade.info("failure sending email notification for client " + client.getIdentifierString());
        }

    }
}
