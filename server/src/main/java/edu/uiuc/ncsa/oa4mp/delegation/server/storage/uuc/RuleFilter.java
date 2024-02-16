package edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc;

import edu.uiuc.ncsa.security.core.util.Iso8601;

import java.text.ParseException;
import java.util.Calendar;
import java.util.HashMap;

import static edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil.getValueSecsOrMillis;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/24 at  1:48 PM
 */
public class RuleFilter {
    public static final String WHEN_AFTER = "after";
    public static final String WHEN_BEFORE = "before";
    public static final String TYPE_ACCESSED = "accessed";
    public static final String TYPE_CREATED = "created";
    public static final String TYPE_MODIFIED = "modified";
    public static final String VERSION_SKIP = "skip";
    public static final String VERSION_ONLY = "only";
    public static final String VERSION_INCLUDE = "include";

    protected void checkWhen(String w) {
        if (w == null) {
            throw new IllegalArgumentException("missing when parameter");
        }
        switch (w) {
            case WHEN_AFTER:
            case WHEN_BEFORE:
                return;
        }
        throw new IllegalArgumentException("unknown when parameter \"" + w + "\"");
    }

    protected void checkType(String t) {
        if (t == null) {
            throw new IllegalArgumentException("missing type parameter");
        }
        switch (t) {
            case TYPE_ACCESSED:
            case TYPE_MODIFIED:
            case TYPE_CREATED:
                return;
        }
        throw new IllegalArgumentException("unknown type parameter \"" + t + "\"");
    }

    public HashMap<String, HashMap<String, DateThingy>> getDatesByWhen() {
        return datesByWhen;
    }

    public void setDatesByWhen(HashMap<String, HashMap<String, DateThingy>> datesByWhen) {
        this.datesByWhen = datesByWhen;
    }

    HashMap<String, HashMap<String, DateThingy>> datesByWhen = new HashMap<>();
    HashMap<String, HashMap<String, DateThingy>> datesByType = new HashMap<>();

    /**
     * This is to be invoked straight from the configuration and the date may be
     * an ISO 8601 date or a raw string like "2000 sec.". The default (as per contract)
     * when no units are specified is seconds.
     *
     * @param when
     * @param type
     * @param rawDate
     */
    public void add(String when, String type, String rawDate) {
        DateThingy dateThingy = null;
        try {
            Calendar calendar = Iso8601.string2Date(rawDate);
            dateThingy = new DateThingy(calendar.getTime());
        } catch (ParseException e) {
            dateThingy = new DateThingy(getValueSecsOrMillis(rawDate, true));
        }
        add(when, type, dateThingy);
    }

    protected void addWhen(String when, String type, DateThingy dateThingy) {
        HashMap<String, DateThingy> m = datesByWhen.get(when);
        if (m == null) {
            m = new HashMap<>();
            datesByWhen.put(when, m);
        }
        m.put(type, dateThingy);
    }

    protected void addType(String when, String type, DateThingy dateThingy) {
        HashMap<String, DateThingy> m = datesByType.get(type);
        if (m == null) {
            m = new HashMap<>();
            datesByType.put(type, m);
        }
        m.put(when, dateThingy);
    }

    public void add(String when, String type, DateThingy dateThingy) {
        checkWhen(when);
        checkType(type);
        addWhen(when, type, dateThingy);
        addType(when, type, dateThingy);
    }

    public DateThingy getDate(String when, String type) {
        HashMap<String, DateThingy> m = datesByWhen.get(when);
        if (m == null) return null;
        return m.get(type);
    }

    public HashMap<String, DateThingy> getByType(String type) {
        return datesByType.get(type);
    }

    public HashMap<String, DateThingy> getByWhen(String when) {
        return datesByWhen.get(when);
    }

    public boolean containsByWhen(String when) {
        return datesByWhen.containsKey(when);
    }

    public boolean containsByType(String type) {
        return datesByType.containsKey(type);
    }

    /**
     * Contains a date by when and type.
     *
     * @param when
     * @param type
     * @return
     */
    public boolean hasDate(String when, String type) {
        HashMap<String, DateThingy> m = datesByWhen.get(when);
        if (m == null) return false;
        return m.containsKey(type);
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        switch (version) {
            case VERSION_INCLUDE:
            case VERSION_ONLY:
            case VERSION_SKIP:
                break;
            default:
                throw new IllegalArgumentException("unknown version filter \"" + version + "\"");
        }
        this.version = version;
    }

    public boolean isVersion(String v) {
        if (version == null) return false;
        return version.equals(v);
    }


    String version;

    public boolean isAllowOverride() {
        return allowOverride;
    }

    public void setAllowOverride(boolean allowOverride) {
        this.allowOverride = allowOverride;
    }

    boolean allowOverride = false;

    /**
     * The argument is assumed to be the parent and this object overrides its values.
     *
     * @param parent
     * @return
     */
    public RuleFilter overrideFromParent(RuleFilter parent) {
        if (!isAllowOverride()) {
            return this;
        }
        RuleFilter rr = null;
        rr = parent.clone();
        if (getVersion() != null) {
            rr.setVersion(getVersion());
        }
        rr.setAllowOverride(isAllowOverride());
        HashMap<String, HashMap<String, DateThingy>> clonedDates = new HashMap<>();
        for (String when : getDatesByWhen().keySet()) {
            HashMap<String, DateThingy> mm = getDatesByWhen().get(when);
            for (String type : mm.keySet()) {
                rr.add(when, type, mm.get(type));
            }
        }
        return rr;
    }

    /**
     * Returns true if the arguments match this filter.
     *
     * @param created
     * @param accessed
     * @param modified
     * @return
     */
    public boolean apply(long created, long accessed, long modified) {
        return checkRule(TYPE_CREATED, created) || checkRule(TYPE_ACCESSED, accessed) || checkRule(TYPE_MODIFIED, modified);
    }

    protected boolean checkRule(String type, long time) {
                             return checkRule(getByType(type), time);
    }
    protected boolean checkRule(HashMap<String, DateThingy> dd, long time) {
        if(dd == null) return true;
        boolean applies = true;
        if (dd.containsKey(WHEN_AFTER)) {
            DateThingy dateThingy = dd.get(WHEN_AFTER);
            if (dateThingy.isRelative()) {
                applies = (System.currentTimeMillis() - dateThingy.relativeDate) <= time;
            } else {
                applies = dateThingy.iso8601.getTime() <= time;
            }
        }
        if(dd.containsKey(WHEN_BEFORE)){
            DateThingy dateThingy = dd.get(WHEN_BEFORE);
            if (dateThingy.isRelative()) {
                applies =applies && time <= (System.currentTimeMillis() - dateThingy.relativeDate);
            } else {
                applies = applies && time <= dateThingy.iso8601.getTime();
            }
        }
        return applies;
    }

    @Override
    protected RuleFilter clone() {
        RuleFilter ruleFilter = new RuleFilter();
        ruleFilter.setAllowOverride(isAllowOverride());
        ruleFilter.setVersion(getVersion());
        HashMap<String, HashMap<String, DateThingy>> clonedDates = new HashMap<>();
        for (String key : datesByWhen.keySet()) {
            HashMap<String, DateThingy> mm = datesByWhen.get(key);
            clonedDates.put(key, (HashMap<String, DateThingy>) mm.clone()); // sholw clone is ok
        }

        ruleFilter.setDatesByWhen(clonedDates);
        return ruleFilter;
    }
}
