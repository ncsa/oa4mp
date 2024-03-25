package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm;

import java.net.URI;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client.USE_SERVER_DEFAULT;

/**
 * Entry for the Client management configuration map.
 * A client management configuration consists of a protocol (such as rfc7591 or oa4mp), whether it is enabled
 * and the full url to the service. Note that at load time, the configuration entry could either specify the
 * full url or it may just specify the endpoint and use the address the service is configured with.
 * <p>Created by Jeff Gaynor<br>
 * on 7/25/19 at  1:42 PM
 */
public class CMConfig {
    public CMConfig() {
    }

    public CMConfig(String protocol, URI uri, boolean enabled) {
        this.protocol = protocol;
        this.uri = uri;
        this.enabled = enabled;
        isConfigured = true;
    }

    @Override
    public String toString() {
        return "CMConfig[" +
                "protocol='" + protocol + '\'' +
                ", uri=" + uri +
                ", enabled=" + enabled +
                ", isConfigured=" + isConfigured +
                ']';
    }

    public String protocol;
    public URI uri;
    public boolean enabled = false;
    public boolean isConfigured = false; // if this has been properly configured.

    /**
     * For client registrations, if there is <b><i>no</i></b> refresh token lifetime
     * given in the request,this is what should be done. The reasonable options are
     * 0 (disable, so no refresh tokens unless a client specifically requests one) or
     * {@link edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client#USE_SERVER_DEFAULT}
     * to use the server default lifetime. <br/><br/>
     * For updates, this is the behavior if the refresh token lifetime is removed from the request.
     * Some installs may want, <i>e.g.</i> to have remove = disable, some may want remove = server default.
     *
     * @return
     */
    public Long getDefaultRefreshTokenLifetime() {
        return defaultRefreshTokenLifetime;
    }

    public void setDefaultRefreshTokenLifetime(Long defaultRefreshTokenLifetime) {
        this.defaultRefreshTokenLifetime = defaultRefreshTokenLifetime;
    }

    Long defaultRefreshTokenLifetime = USE_SERVER_DEFAULT;
}
