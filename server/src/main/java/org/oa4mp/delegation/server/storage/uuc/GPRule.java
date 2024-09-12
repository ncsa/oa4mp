package org.oa4mp.delegation.server.storage.uuc;

/**
 * A rule with a grace period
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/24 at  4:45 PM
 */
public abstract class GPRule extends MetaRule{
    public long getGracePeriod() {
        return gracePeriod;
    }

    public void setGracePeriod(long gracePeriod) {
        this.gracePeriod = gracePeriod;
    }

    long gracePeriod = -1L;

    public boolean isGracePeriodSet(){
        return gracePeriod != -1L;
    }

    public abstract boolean applies(Long created, Long accessed, Long modified);

}
