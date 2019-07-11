package edu.uiuc.ncsa.myproxy.oa4mp.server.util;

import edu.uiuc.ncsa.security.delegation.storage.BaseClient;
import edu.uiuc.ncsa.security.servlet.NotificationEvent;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/14/12 at  5:39 PM
 */
public class NewClientEvent extends NotificationEvent {
    public NewClientEvent(Object source, BaseClient client) {
        super(source);
        this.client = client;
    }

    BaseClient client;

    public BaseClient getClient() {
        return client;
    }
}
