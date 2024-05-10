package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;

import java.net.URI;
import java.util.HashMap;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/25/19 at  1:44 PM
 */
public class CMConfigs extends HashMap<String, CMConfig> implements ClientManagementConstants {
    /**
     * Globally enables or disables this entire facility.
     *
     * @return
     */
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    boolean enabled = true;

    public CMConfig put(CMConfig cmEntry) {
        return put(cmEntry.protocol, cmEntry);
    }

    /**
     * Create and entry from a bunch of strings. This is a factory method.
     *
     * @param protocol
     * @param serverAddress
     * @param endpoint
     * @param rawURI
     * @param enabled
     * @return
     */
    protected static CMConfig createConfigEntry(String protocol,
                                             String serverAddress,
                                             String endpoint,
                                             String rawURI,
                                             String enabled) {
        if (protocol == null || protocol.isEmpty()) {
            throw new IllegalArgumentException("Error: missing protocol");
        }
        // if there is an explicit registration uri , we don't need a server address, otherwise fail
        if ((rawURI == null || rawURI.isEmpty()) && (serverAddress == null || serverAddress.isEmpty())) {
            throw new IllegalArgumentException("Error: Missing server address and registration address.");
        }
        URI uri = createURIFromProtocol(protocol, serverAddress, endpoint, rawURI);
        boolean isEnabled = true; // default
        try {
            isEnabled = Boolean.parseBoolean(enabled);
        } catch (Throwable t) {
            // fine. Ignore it
        }

        CMConfig cmConfig = new CMConfig(protocol, uri, isEnabled);
        cmConfig.setEndpoint(endpoint);
        return cmConfig;
    }

    public static CMConfig createConfigEntry(String protocol,
                                                 String serverAddress,
                                                 String endpoint,
                                                 String rawURI,
                                                 String enabled,
                                                 String templateIdentifier,
                                                 String rawAnonymousOK,
                                                 String rawAutoApprove,
                                             String rawAutoApproverName) {

        if (protocol == null || protocol.isEmpty()) {
            throw new IllegalArgumentException("Error: missing protocol");
        }
        switch(protocol){
            case RFC_7591_VALUE:
                return create7591ConfigEntry(protocol,
                        serverAddress,
                        endpoint,
                        rawURI,
                        enabled,
                        templateIdentifier,
                        rawAnonymousOK,
                        rawAutoApprove,
                        rawAutoApproverName);
            case RFC_7592_VALUE:
            case OA4MP_VALUE:
                if(!(isTrivial(templateIdentifier) && isTrivial(rawAutoApprove) && isTrivial(rawAnonymousOK))){
                    throw new IllegalArgumentException("Error: unsupported attributes for protocol \"" + protocol + "\"");
                }
                return createConfigEntry(protocol,
                        serverAddress,
                        endpoint,
                        rawURI,
                        enabled);
            default:
                throw new IllegalArgumentException("Error: unknown protocol");
        }

    }

    protected static CM7591Config create7591ConfigEntry(String protocol,
                                                 String serverAddress,
                                                 String endpoint,
                                                 String rawURI,
                                                 String enabled,
                                                 String templateIdentifier,
                                                 String rawAnonymousOK,
                                                 String rawAutoApprove,
                                                        String rawAutoApproverName) {
        if (protocol == null || protocol.isEmpty()) {
            throw new IllegalArgumentException("Error: missing protocol");
        }
        // if there is an explicit registration uri , we don't need a server address, otherwise fail
        if ((rawURI == null || rawURI.isEmpty()) && (serverAddress == null || serverAddress.isEmpty())) {
            throw new IllegalArgumentException("Error: Missing server address and registration address.");
        }
        URI uri = createURIFromProtocol(protocol, serverAddress, endpoint, rawURI);
        boolean isEnabled = true; // default
        try {
            isEnabled = Boolean.parseBoolean(enabled);
        } catch (Throwable t) {
            // fine. Ignore it
        }
        boolean autoApprove = false;
        try {
            autoApprove = Boolean.parseBoolean(rawAutoApprove);
        } catch (Throwable t) {
            // fine. Ignore it
        }

        boolean anonymousOK = false;
        try {
            anonymousOK = Boolean.parseBoolean(rawAnonymousOK);
        } catch (Throwable t) {
            // fine. Ignore it
        }

        Identifier template = null;
        if (!isTrivial(templateIdentifier)) {
            template = BasicIdentifier.newID(templateIdentifier);
        }

        CM7591Config config = new CM7591Config(protocol, uri, isEnabled, template, anonymousOK, autoApprove);

        if(!isTrivial(rawAutoApproverName)){
            config.autoApproverName = rawAutoApproverName;
        }

        config.setEndpoint(endpoint);
        return config;
    }


    protected static URI createURIFromProtocol(String protocol,
                                               String rawAddress,
                                               String endpoint,
                                               String rawURI) {
        // assumption is that all parameters have been vetted. If the endpoint is missing, the
        // default for the protocol is created.
        boolean addSlash = !rawAddress.endsWith("/");

        if (rawURI == null || rawURI.isEmpty()) {
            if (endpoint == null || endpoint.isEmpty()) {
                // create and return the correct default endpoint
                if (protocol.equals(ClientManagementConstants.OA4MP_VALUE)) {
                    return URI.create(rawAddress + (addSlash ? "/" : "") + ClientManagementConstants.DEFAULT_OA4MP_ENDPOINT);
                }
                if (protocol.equals(ClientManagementConstants.RFC_7591_VALUE) || protocol.equals(ClientManagementConstants.RFC_7592_VALUE)) {
                    return URI.create(rawAddress + (addSlash ? "/" : "") + ClientManagementConstants.DEFAULT_RFC7591_ENDPOINT);
                }
                throw new IllegalArgumentException("Error: Unknown protocol \"" + protocol + "\"");
            } else {
                return URI.create(rawAddress + (addSlash ? "/" : "") + endpoint);
            }
        }
        return URI.create(rawURI);
    }

    public CMConfig getOA4MPConfig() {
        return get(ClientManagementConstants.OA4MP_VALUE);
    }

    public CM7591Config getRFC7591Config() {
        return (CM7591Config) get(ClientManagementConstants.RFC_7591_VALUE);
    }

    public CMConfig getRFC7592Config() {
        return get(ClientManagementConstants.RFC_7592_VALUE);
    }

    public boolean hasOA4MPConfig() {
        return getOA4MPConfig() != null;
    }

    public boolean hasRFC7591Config() {
        return getRFC7591Config() != null;
    }

    public boolean hasRFC7592Config() {
        return getRFC7592Config() != null;
    }

}
