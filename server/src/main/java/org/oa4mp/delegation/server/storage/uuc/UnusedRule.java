package org.oa4mp.delegation.server.storage.uuc;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/24 at  4:37 PM
 */
public class UnusedRule extends GPRule{
    @Override
    public boolean applies(Long created, Long accessed, Long modified) {
        return accessed == null && (created + getGracePeriod() < System.currentTimeMillis());
    }
}
