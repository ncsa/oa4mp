package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm;

import java.net.URI;
import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/25/19 at  1:44 PM
 */
public class CMConfigs extends HashMap<String, CMConfig> {
    public CMConfig put(CMConfig cmEntry) {
        return put(cmEntry.protocol, cmEntry);
    }

    /**
     * Create and entry from a bunch of strings. This is a factory method.
     * @param protocol
     * @param serverAddress
     * @param endpoint
     * @param rawURI
     * @param enabled
     * @return
     */
    public static CMConfig createConfigEntry(String protocol,
                                             String serverAddress,
                                             String endpoint,
                                             String rawURI,
                                             String enabled) {
        if (protocol == null || protocol.isEmpty()) {
            throw new IllegalArgumentException("Error: missing protocol");
        }
        // if there is an explicit registration uri , we don't need a server address, otherwise fail
        if((rawURI  == null || rawURI.isEmpty()) && (serverAddress == null || serverAddress.isEmpty())) {
            throw new IllegalArgumentException("Error: Missing server address and registration address.");
        }
        URI uri = createURIFromProtocol(protocol,serverAddress,endpoint,rawURI);
        boolean isEnabled = true; // default
        try {
            isEnabled = Boolean.parseBoolean(enabled);
        } catch (Throwable t) {
            // fine. Ignore it
        }

        return new CMConfig(protocol, uri, isEnabled);
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

    public CMConfig getOA4MPConfig(){
        return get(ClientManagementConstants.OA4MP_VALUE);
    }
    public CMConfig getRFC7591Config(){
        return get(ClientManagementConstants.RFC_7591_VALUE);
    }
    public CMConfig getRFC7592Config(){
        return get(ClientManagementConstants.RFC_7592_VALUE);
    }

    public boolean hasOA4MPConfig(){
        return getOA4MPConfig() != null;
    }

    public boolean hasRFC7591Config(){
        return getRFC7591Config() != null;
    }

    public boolean hasRFC7592Config(){
        return getRFC7592Config() != null;
    }

}
