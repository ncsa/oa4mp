package edu.uiuc.ncsa.myproxy.oa4mp.server.util;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.servlet.Notifier;
import edu.uiuc.ncsa.security.util.mail.MailUtil;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;

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

    public NewClientNotifier(MailUtil mailUtil, MyLoggingFacade loggingFacade) {
        super(mailUtil, loggingFacade);
    }

    @Override
    public void fireNewClientEvent(NewClientEvent notificationEvent) {
        if (!mailUtil.isEnabled()) {
            return;
        }
        Client client = notificationEvent.getClient();
        HashMap<String, String> replacements = new HashMap<String, String>();
        replacements.put(NAME, client.getName());
        replacements.put(EMAIL, client.getEmail());
        replacements.put(HOME_URI, client.getHomeUri());
        replacements.put(FAILURE_URI, client.getErrorUri());
        replacements.put(CREATION_TIME, client.getCreationTS().toString());
        replacements.put(IDENTIFIER, client.getIdentifierString());
        replacements.put(LIMITED_PROXY, Boolean.toString(client.isProxyLimited()));
        try {
            replacements.put("host", InetAddress.getLocalHost().getCanonicalHostName());
        } catch (UnknownHostException e) {
            loggingFacade.warn("Error: Could not resolve localhost, so could not put full name into message");
            replacements.put("host", "localhost");
        }

        boolean rc = mailUtil.sendMessage(replacements);
        if (rc) {
            loggingFacade.info("sending email notification for client " + client.getIdentifierString());
        } else {
            loggingFacade.info("failure sending email notification for client " + client.getIdentifierString());
        }

    }
}
