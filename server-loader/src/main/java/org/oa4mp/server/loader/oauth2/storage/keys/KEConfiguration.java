package org.oa4mp.server.loader.oauth2.storage.keys;

import org.oa4mp.server.loader.oauth2.OA2SE;

import static org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader.GRACE_PERIOD_NOT_CONFIGURED;

public class KEConfiguration {
    /**
     * The cache grace period. This set for the VI based on their system's cache policy.
     */
    public long cacheGracePeriod = GRACE_PERIOD_NOT_CONFIGURED;// 24 hours
    /**
     * The access token grace period. This is set for the VI using their access token lifetime.
     */
    public long atGracePeriod = GRACE_PERIOD_NOT_CONFIGURED;
    /**
     * Has the user enabled or disabled this explicitly?
     */
    public boolean enabled = true;
    /**
     * Use by VIs. If the current configuration should inherit from the system/default configuration.
     * if a value is set to (@link OA2CFConfigurationLoader#GRACE_PERIOD_NOT_CONFIGURED}, then
     * the server value is used.
     */
    public boolean allowOverride = false;

    /**
     * Returns true if both the cache and access token grace periods are configured.
     * @return
     */
    public boolean isConfgured(){return cacheGracePeriod != GRACE_PERIOD_NOT_CONFIGURED && atGracePeriod != GRACE_PERIOD_NOT_CONFIGURED;}

    /**
     * Is this configuration in the system configuration file? At most one KE configuration can
     * have this true. There is always a configuraation in {@link OA2SE#getKeConfiguration()}
     * and <b>if</b> that was specified by the user, this will be true. This lets you see if
     * you are working with a system supplied configuration (false) or not (true).
     */
    public boolean isInConfigFile = false;

    @Override
    public String toString() {
        return "KEConfiguration{" +
                "cacheGracePeriod=" + cacheGracePeriod +
                ", atGracePeriod=" + atGracePeriod +
                ", enabled=" + enabled +
                ", allowOverride=" + allowOverride +
                ", isInConfigFile=" + isInConfigFile +
                '}';
    }
}
