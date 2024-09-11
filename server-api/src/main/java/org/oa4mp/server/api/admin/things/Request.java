package org.oa4mp.server.api.admin.things;

import org.oa4mp.delegation.common.storage.clients.BaseClient;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/10/16 at  4:45 PM
 */
public class Request {
    BaseClient subject;
    BaseClient target;
    JSONObject content;

    public Request( BaseClient subject, BaseClient target,  JSONObject content) {
        this.content = content;
        this.subject = subject;
        this.target = target;
    }

}
