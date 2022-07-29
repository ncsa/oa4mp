package edu.uiuc.ncsa.oa4mp.delegation.oa2.server;

import edu.uiuc.ncsa.oa4mp.delegation.server.request.AGRequest;

import javax.servlet.http.HttpServletRequest;

/**
 * This has the lifetime in it directly, since the grant request is done <i>before</i> the transaction
 * can exist. Hence it cannot have a dependency on the transaction.
 * <p>Created by Jeff Gaynor<br>
 * on 12/1/20 at  10:04 AM
 */
public class AGRequest2 extends AGRequest {
    public AGRequest2(HttpServletRequest request, long lifetime) {
        super(request, null);
        this.lifetime = lifetime;
    }


    public long getLifetime() {
        return lifetime;
    }

    public void setLifetime(long lifetime) {
        this.lifetime = lifetime;
    }

    long lifetime;


}
