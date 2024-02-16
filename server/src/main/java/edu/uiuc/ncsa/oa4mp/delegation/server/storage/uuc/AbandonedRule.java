package edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/24 at  4:37 PM
 */
public class AbandonedRule extends GPRule{

    /**
     * Returns true if the argument fulfills this rule. So that means the
     * date is outside the grace period
     * @param created
     * @param accessed
     * @param modified
     * @return
     */
    @Override
    public boolean applies(Long created, Long accessed, Long modified) {
        return  accessed + getGracePeriod() < System.currentTimeMillis();
    }
}
