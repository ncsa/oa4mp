package org.oa4mp.server.loader.oauth2.cm;

import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;

import java.net.URI;

import static org.oa4mp.server.loader.oauth2.storage.clients.OA2Client.USE_SERVER_DEFAULT;

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
    /**
     * The last component of the uri. This is set as a convenience since it is used for
     * determining the requested version of this API.
     */
    public boolean enabled = false;

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    String endpoint;
    public boolean isConfigured = false; // if this has been properly configured.

    /**
     * For client registrations, if there is <b><i>no</i></b> refresh token lifetime
     * given in the request,this is what should be done. The reasonable options are
     * 0 (disable, so no refresh tokens unless a client specifically requests one) or
     * {@link OA2Client#USE_SERVER_DEFAULT}
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
