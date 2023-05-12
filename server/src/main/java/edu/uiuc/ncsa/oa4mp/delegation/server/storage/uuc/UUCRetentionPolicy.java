package edu.uiuc.ncsa.oa4mp.delegation.server.storage.uuc;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.cache.RetentionPolicy;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.cli.StoreArchiver;

import java.sql.Timestamp;
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
        if(storeArchiver == null){
            storeArchiver = new StoreArchiver(store);
        }
        return storeArchiver;
    }

    StoreArchiver storeArchiver = null;
    UUCConfiguration config;
    Store store;

    public boolean retain(String id, Timestamp create, Timestamp lastModified) {
        return retain(BasicIdentifier.newID(id), create.getTime(), lastModified.getTime());
    }

    public boolean retain(Identifier id, long create, long lastModified) {
       if((!config.deleteVersions)  && getStoreArchiver().isVersion(id)){
           return true;
        }
       if(config.hasWhitelist()){
           if(config.getWhiteList().contains(id)) return true;
       }
       if(config.hasWhitelistRegex()){
           for(String rx : config.getWhitelistRegex()){
               if(id.toString().matches(rx)){return true;}
           }
       }
       if(config.hasBlacklist()){
           if(config.getBlacklist().contains(id)){return false;}
       }
       if(config.hasBlacklistRegex()){
           for(String rx : config.getBlacklistRegex()){
               if(id.toString().matches(rx)){return false;}
           }
       }
       long now = System.currentTimeMillis();
      return (now<(lastModified + config.gracePeriod)) && (now<(create+config.gracePeriod));
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
