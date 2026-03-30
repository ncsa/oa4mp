package org.oa4mp.server.loader.oauth2.storage.keys;

import org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader;

public class KEConfiguration {
    public long cacheGracePeriod = 24*3600*1000L; // 24 hours
    public long atGracePeriod = OA2CFConfigurationLoader.MAX_ACCESS_TOKEN_LIFETIME_DEFAULT;
    public boolean enabled = true;
    public boolean allowOverride = true;
}
