package org.oa4mp.delegation.server.storage.uuc;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/24 at  1:45 PM
 */
public class ListRule extends MetaRule {
    public boolean isBlackList() {
        return blackList;
    }

    public void setBlackList(boolean blackList) {
        this.blackList = blackList;
    }

    boolean blackList = false;

    public void setIdList(List<Identifier> idList) {
        this.idList = idList;
    }

    public void setRegexList(List<String> regexList) {
        this.regexList = regexList;
    }

    List<Identifier> idList;

    public List<Identifier> getIDlist() {
        if (idList == null) {
            idList = new ArrayList<>();
        }
        return idList;
    }

    List<String> regexList;

    public List<String> getRegexList() {
        if (regexList == null) {
            regexList = new ArrayList<>();
        }
        return regexList;
    }

    public RuleFilter getRuleFilter() {
        if (ruleFilter == null) {
            ruleFilter = new RuleFilter();
        }
        return ruleFilter;
    }

    public void setRuleFilter(RuleFilter ruleFilter) {
        this.ruleFilter = ruleFilter;
    }

    public boolean hasRuleFilter() {
        return ruleFilter != null;
    }

    RuleFilter ruleFilter;

    /**
     * Does this rule apply to this list? This means that the argument fulfills the
     * conditions in the list.
     *
     * @param id
     * @return
     */
    public boolean applies(Identifier id) {
        return applyToID(id) || applyToRegex(id.toString());
    }

    protected boolean applyToID(Identifier id) {
        return getIDlist().contains(id);
    }

    protected boolean applyToID(String id) {
        return getIDlist().contains(BasicIdentifier.newID(id));
    }

    protected boolean applyToRegex(String id) {
        for (String rx : getRegexList()) {
            if (id.matches(rx)) {
                return true;
            }
        }
        return false;
    }

    public boolean applies(String id) {
        return applyToID(id) || applyToRegex(id);
    }
}
