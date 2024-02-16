package edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.cache.RetentionPolicy;
import edu.uiuc.ncsa.security.storage.cli.StoreArchiver;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/11/23 at  6:45 AM
 */
public class UUCRetentionPolicy implements RetentionPolicy {
    public UUCRetentionPolicy(Store store, UUCConfiguration config) {
        this.config = config;
        this.store = store;
    }

    public StoreArchiver getStoreArchiver() {
        if (storeArchiver == null) {
            storeArchiver = new StoreArchiver(store);
        }
        return storeArchiver;
    }

    StoreArchiver storeArchiver = null;
    UUCConfiguration config;
    Store store;

    /**
     * Retention call. This returns an array of object. The zero-th element is always a boolean
     * with the value (1 = retain, 0 = do not retain) and <b>if false</b> the second
     * value is the name of the rule that was invoked, see {@link UUCConfiguration}.
     * @param id
     * @param create
     * @param lastAccessed
     * @param lastModified
     * @return
     */
    public int[] retain(Identifier id, Date create, Date lastAccessed, Date lastModified) {
        Long created = create==null?null:create.getTime();
        Long accessed = lastAccessed==null?null: lastAccessed.getTime();
        Long modified = lastModified==null?null: lastModified.getTime();
        if(config.hasFilter()){
            HashMap<String, DateThingy> createdDates = config.getFilter().getByType(RuleFilter.TYPE_CREATED);
            boolean applies = false;
            if(createdDates.containsKey(RuleFilter.WHEN_AFTER)){
                DateThingy dateThingy = createdDates.get(RuleFilter.WHEN_AFTER);
                if(dateThingy.isRelative()){
                     applies = created + dateThingy.relativeDate <= System.currentTimeMillis();
                } else{
                     applies = created <= dateThingy.iso8601.getTime();
                }
            }
            if(createdDates.containsKey(RuleFilter.WHEN_BEFORE)){
                DateThingy dateThingy = createdDates.get(RuleFilter.WHEN_BEFORE);
                if(dateThingy.isRelative()){
                     applies = applies && (  System.currentTimeMillis() <= created + dateThingy.relativeDate);
                } else{
                     applies = applies && (  dateThingy.iso8601.getTime() <= created);
                }
            }
            if(applies) return new int[]{1};
        }
        if (config.hasCreatedAfter()) {
            if (created <= config.createdAfter.getTime()) return new int[]{1};
        }
/*        if ((!config.deleteVersions) && getStoreArchiver().isVersion(id)) {
            return true;
        }*/

        if(config.hasWhitelist()){
            if(config.getWhiteList().applies(id)) return new int[]{1};
        }

        if(config.hasUnusedRule()){
            if(config.getUnusedRule().applies(created, accessed, modified)) return new int[]{0,UUCConfiguration.UNUSED_RULE};
        }

        if(config.hasAbandonedRule()){
            if(config.getAbandonedRule().applies(created, accessed, modified)) return new int[]{0, UUCConfiguration.ABANDONED_RULE};
        }

        if(config.hasBlacklist()){
            if(config.getBlackList().applies(id)) return new int[]{0, UUCConfiguration.BLACKLIST_RULE};
        }

        return new int[]{1};
    }


    @Override
    public boolean retain(Object key, Object value) {
        return false;
    }

    @Override
    public Map getMap() {
        return null;
    }

    @Override
    public boolean applies() {
        return false;
    }
}
