package org.oa4mp.server.loader.oauth2.storage.keys;

import static org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader.GRACE_PERIOD_NOT_CONFIGURED;

public class KEConfiguration {
    public long cacheGracePeriod = GRACE_PERIOD_NOT_CONFIGURED; // 24 hours
    public long atGracePeriod = GRACE_PERIOD_NOT_CONFIGURED;
    public boolean enabled = true;
    public boolean allowOverride = false;
    public boolean isConfgured(){return cacheGracePeriod != GRACE_PERIOD_NOT_CONFIGURED && atGracePeriod != GRACE_PERIOD_NOT_CONFIGURED;}
}
