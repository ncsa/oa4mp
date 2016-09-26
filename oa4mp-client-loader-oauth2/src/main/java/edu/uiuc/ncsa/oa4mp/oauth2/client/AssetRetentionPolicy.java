package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.RetentionPolicy;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;

import java.util.Date;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/15/14 at  12:23 PM
 */
public class AssetRetentionPolicy implements RetentionPolicy {

    public AssetRetentionPolicy(AssetStore rts) {
          this.rts = rts;
      }

      AssetStore rts;

      /**
       * Always true for every element in the cache.
       * @return
       */
      @Override
      public boolean applies() {
          return true;
      }

      @Override
      public boolean retain(Object key, Object value) {
          Identifier identifier = (Identifier) key;
          OA2Asset oa2Asset = (OA2Asset) value;
          RefreshToken rt = oa2Asset.getRefreshToken();
          if(rt == null || rt.getToken()== null){
              return true;
          }
          // Now we have to check against the timestamp on the original and the expires in flag.
           Date creationTS = DateUtils.getDate(oa2Asset.getRefreshToken().getToken());

          if(creationTS.getTime() + oa2Asset.getRefreshToken().getExpiresIn() <= System.currentTimeMillis()){
              return true;
          }
          return false;
      }

      @Override
      public Map getMap() {
          return rts;
      }
}
