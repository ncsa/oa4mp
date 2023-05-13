package edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.Iso8601;

import java.time.LocalTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Typical configuration example:
 * <pre>
 *  &lt;unusedClientCleanup gracePeriod="6 hr"
 *                                 alarms="6:00"
 *                                 deleteVersions="false"
 *                                 enabled="true"
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
    public boolean enabled;
    public long gracePeriod;
    public long interval;
    public boolean testMode = false; // internally set flag to only return items to delete.
    public Collection<LocalTime> alarms = null;

    public boolean hasAlarms() {
        return alarms != null;
    }

    public boolean deleteVersions = false;
    public List<Identifier> whiteList = null;
    public List<Identifier> blacklist = null;

    public List<String> whitelistRegex = null;
    public List<String> blacklistRegex = null;

    public void whiteList(Identifier id) {
        getWhiteList().add(id);
    }

    public List<Identifier> getWhiteList() {
        if (whiteList == null) {
            whiteList = new ArrayList<>();
        }
        return whiteList;
    }

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

    public Long getLastAccessed() {
        return lastAccessed;
    }

    public Long lastAccessed = null;

    public boolean unusedClientsOnly(){
        return lastAccessed == null;
    }

    public Long lastAccessedAfter = null;
    public boolean hasLastAccessedAfter(){
        return lastAccessedAfter!=null;
    }
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

    @Override
    public String toString() {
      return toString(false);
    }

    public String toString(boolean prettyPrint) {
        return "UUCConfiguration{" +
                (prettyPrint ? "\n   " : "") + "enabled=" + enabled +
                (prettyPrint ? "\n   " : "") + "lastAccessed=" + (lastAccessed==null?"never": Iso8601.date2String(lastAccessed)) +
                (prettyPrint ? ",\n   " : "") + "expiration=" + gracePeriod +
                (prettyPrint ? ",\n   " : "") + "interval=" + interval +
                (prettyPrint ? ",\n   " : "") + "testMode=" + testMode +
                (prettyPrint ? ",\n   " : "") + "alarms=" + alarms +
                (prettyPrint ? ",\n   " : "") + "deleteVersions=" + deleteVersions +
                (prettyPrint ? ",\n   " : "") + "whiteList=" + whiteList +
                (prettyPrint ? ",\n   " : "") + "blacklist=" + blacklist +
                (prettyPrint ? ",\n   " : "") + "whitelistRegex=" + whitelistRegex +
                (prettyPrint ? ",\n   " : "") + "blacklistRegex=" + blacklistRegex +
                "\n}";
    }
}
