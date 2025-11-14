package org.oa4mp.server.api.util;

import edu.uiuc.ncsa.security.util.events.NotificationEvent;
import org.oa4mp.delegation.common.storage.clients.BaseClient;

public class UpdateClientEvent extends NotificationEvent {
    public UpdateClientEvent(Object source, BaseClient client) {
        super(source);
        this.client = client;
    }
    BaseClient client;

    public BaseClient getClient() {
        return client;
    }
}
