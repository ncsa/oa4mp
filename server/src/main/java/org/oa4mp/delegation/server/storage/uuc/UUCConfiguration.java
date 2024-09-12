package org.oa4mp.delegation.server.storage.uuc;

import java.time.LocalTime;
import java.util.Collection;
import java.util.Date;

/**
 * Typical configuration example:
 * <pre>
 *  &lt;unusedClientCleanup gracePeriod="6 hr"
 *                                 alarms="6:00"
 *                                 deleteVersions="false"
 *                                 enabled="true"
 *                                 createdNotBefore=ISO 8601 time
 *                                 interval="1 hr"&gt;
 *      &lt;whitelist&gt;
 *         &lt;clientID&gt;id...&lt;/clientID&gt;
 *         &lt;clientID&gt;id...&lt;/clientID&gt;
 *         &lt;clientID&gt;id...&lt;/clientID&gt;
 *         &lt;regex&gt;^localhost.*&lt;/regex&gt;
 *         &lt;regex&gt;^urn.*&lt;/regex&gt;
 *      &lt;/whitelist&gt;
 *      &lt;blacklist&gt;
 *         &lt;clientID&gt;id...&lt;/clientID&gt;
 *         &lt;regex&gt;^template.*&lt;/regex&gt;
 *      &lt;/blacklist&gt;
 *  &lt;/unusedClientCleanup&gt;
 * </pre>
 * <p>Created by Jeff Gaynor<br>
 * on 5/11/23 at  6:43 AM
 */
public class UUCConfiguration {
    public static final long UUC_LAST_ACCESSED_NEVER_VALUE = -1L;
    public boolean enabled;
    public long gracePeriod;
    public long interval;
    public boolean testMode = false; // internally set flag to only return items to delete.
    public Collection<LocalTime> alarms = null;

    public static final int UNUSED_RULE = 100;
    public static final int ABANDONED_RULE =101;
    public static final int BLACKLIST_RULE =102;
    public static final int WHITELIST_RULE =103;

    public static final int[] allRules = new int[]{UNUSED_RULE,ABANDONED_RULE,BLACKLIST_RULE,WHITELIST_RULE};
    public RuleFilter getFilter(int rule){
        switch (rule){
            case UNUSED_RULE:
                return getUnusedRule().getFilter();
            case ABANDONED_RULE:
                return getAbandonedRule().getFilter();
            case WHITELIST_RULE:
                return getWhiteList().getFilter();
            case BLACKLIST_RULE:
                return getBlackList().getFilter();
            default:
                return null;
        }
    }
    public boolean hasFilter(int rule){
        return getFilter(rule) != null;
    }

    public boolean hasSubFilter(){
       for(int r : allRules){
           if(hasFilter(r)) return true;
       }
       return false;
    }

    public MetaRule getRule(int rule){
        switch (rule){
            case UNUSED_RULE:
                return getUnusedRule();
            case ABANDONED_RULE:
                return getAbandonedRule();
            case WHITELIST_RULE:
                return getWhiteList();
            case BLACKLIST_RULE:
                return getBlackList();
            default:
                return null;
        }
    }
    public boolean hasRule(int rule){
        switch (rule){
            case UNUSED_RULE:
                return hasUnusedRule();
            case ABANDONED_RULE:
                return hasAbandonedRule();
            case WHITELIST_RULE:
                return hasWhitelist();
            case BLACKLIST_RULE:
                return hasBlacklist();
            default:
                return false;
        }
    }
    public static final String ACTION_TEST="test";
    public static final String ACTION_ARCHIVE="archive";
    public static final String ACTION_DELETE="delete";

    public RuleFilter getFilter() {
        return filter;
    }

    public void setFilter(RuleFilter filter) {
        this.filter = filter;
    }

    RuleFilter filter = null;

    public boolean hasFilter(){
        return filter != null;
    }

    public ListRule getBlackList() {
        return blackList;
    }

    public void setBlackList(ListRule blackList) {
        this.blackList = blackList;
    }

    ListRule blackList;
    public void setWhiteList(ListRule whiteList) {
        this.whiteList = whiteList;
    }

    public ListRule getWhiteList() {
        return whiteList;
    }
   public boolean hasWhitelist(){
        return whiteList != null;
   }
   public boolean hasBlacklist(){
        return blackList!=null;
   }
    ListRule whiteList;
    public boolean isLastAccessedNever() {
        return lastAccessedNever;
    }

    public void setLastAccessedNever(Boolean lastAccessedNever) {
        this.lastAccessedNever = lastAccessedNever;
    }

    Boolean lastAccessedNever = null;

    boolean hasLastAccessedNever(){
        return lastAccessedNever != null;
    }
    public boolean getDebugOn() {
        return debugOn;
    }

    public void setDebugOn(boolean debugOn) {
        this.debugOn = debugOn;
    }

    boolean debugOn = false;
    /**
     * Do not process clients whose creation date is before this. The intent is that systems that
     * are introducing UUC may have several  older clients that may be used infrequently or in the case of
     * upgrading the system from a much older version of OA4MP, the information simply has not had time
     * to accrue.
     *
     * @return
     */
    public Date getCreatedAfter() {
        return createdAfter;
    }

    public void setCreatedAfter(Date createdAfter) {
        this.createdAfter = createdAfter;
    }

    Date createdAfter = null;

    public boolean hasCreatedAfter() {
        return createdAfter != null;
    }

    public Date getCreatedBefore() {
        return createdBefore;
    }

    public void setCreatedBefore(Date createdBefore) {
        this.createdBefore = createdBefore;
    }

    Date createdBefore = null;

    public boolean hasCreatedBefore() {
        return createdBefore != null;
    }

    public boolean hasAlarms() {
        return alarms != null;
    }

    public boolean deleteVersions = false;

    public boolean hasUnusedRule(){
        return unusedRule != null;
    }
    public boolean hasAbandonedRule(){
        return abandonedRule != null;
    }
/*    public List<Identifier> whiteList = null;
    public List<Identifier> blacklist = null;

    public List<String> whitelistRegex = null;
    public List<String> blacklistRegex = null;*/

/*
    public void whiteList(Identifier id) {
        getWhiteList().add(id);
    }

    public List<Identifier> getWhiteList() {
        if (whiteList == null) {
            whiteList = new ArrayList<>();
        }
        return whiteList;
    }
*/

/*
    public List<Identifier> getBlacklist() {
        if (blacklist == null) {
            blacklist = new ArrayList<>();
        }
        return blacklist;
    }

    public List<String> getWhitelistRegex() {
        if (whitelistRegex == null) {
            whitelistRegex = new ArrayList<>();
        }
        return whitelistRegex;
    }

    public List<String> getBlacklistRegex() {
        if (blacklistRegex == null) {
            blacklistRegex = new ArrayList<>();
        }
        return blacklistRegex;
    }
*/

/*
    public Long getLastAccessedBefore() {
        return lastAccessedBefore;
    }
*/

    /**
     * If set, this will be the upper bound on the last access date. Therefore, for a client whose
     * last accesed timestamp is L
     * <pre>L ∈ [lastAccessedAfter, lastAccessedBefore]</pre>
     */
    public Long lastAccessedBefore = null;

    public boolean unusedClientsOnly() {
        return lastAccessedBefore == null || lastAccessedBefore == UUC_LAST_ACCESSED_NEVER_VALUE;
    }

    /**
     * If this is set, it is a lower bound for last accessed, so the utility will look for
     * unused clients last accessed after this date.
     */
    public Long lastAccessedAfter = null;

    public boolean hasLastAccessedAfter() {
        return lastAccessedAfter != null;
    }

    public boolean hasLastAccessedBefore() {
        return lastAccessedBefore != null;
    }
/*
    public void whiteList(String regex) {
        getWhitelistRegex().add(regex);
    }

    public void blackList(String regex) {
        getBlacklistRegex().add(regex);
    }

    public void blackList(Identifier id) {
        getBlacklist().add(id);
    }

    public boolean hasWhitelist() {
        return whiteList != null;
    }

    public boolean hasBlacklist() {
        return blacklist != null;
    }

    public boolean hasWhitelistRegex() {
        return whitelistRegex != null;
    }

    public boolean hasBlacklistRegex() {
        return blacklistRegex != null;
    }
*/

    /*   @Override
       public String toString() {
         return toString(false);
       }
   */
    public String toString(boolean prettyPrint) {
        if (!prettyPrint) return toString();
       return null;
    }

    public UnusedRule getUnusedRule() {
        return unusedRule;
    }

    public void setUnusedRule(UnusedRule unusedRule) {
        this.unusedRule = unusedRule;
    }

    UnusedRule unusedRule = null;

    public AbandonedRule getAbandonedRule() {
        return abandonedRule;
    }

    public void setAbandonedRule(AbandonedRule abandonedRule) {
        this.abandonedRule = abandonedRule;
    }

    AbandonedRule abandonedRule = null;


}

/*

 "        alarms=" + alarms + ",\n" +
 "     blacklist=" +  + ",\n" +
 "blacklistRegex=" +  + ",\n" +
 "deleteVersions=" +  + ",\n" +
 "       enabled=" +  + ",\n" +
 "   gracePeriod=" +  + ",\n" +
 "      interval=" +  + ",\n" +
 "  lastAccessed=" +  + ",\n" +
 "      testMode=" +  + ",\n" +
 "     whiteList=" +  + ",\n" +
 "whitelistRegex=" +
 */