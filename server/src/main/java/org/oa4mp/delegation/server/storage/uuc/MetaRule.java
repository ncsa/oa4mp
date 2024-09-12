package org.oa4mp.delegation.server.storage.uuc;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/24 at  3:46 PM
 */
public abstract class MetaRule {
    public RuleFilter getFilter() {
        return filter;
    }

    public void setFilter(RuleFilter filter) {
        this.filter = filter;
    }

    public boolean hasFilter(){
        return filter != null;
    }
    RuleFilter filter;

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        switch (action){
            case UUCConfiguration.ACTION_ARCHIVE:
            case UUCConfiguration.ACTION_DELETE:
            case UUCConfiguration.ACTION_TEST:
                this.action = action;
                break;
            default:
                throw new IllegalArgumentException("unknown action \"" + action + "\"");
        }
    }

    String action;
}
