package org.oa4mp.server.loader.oauth2.cm;

import edu.uiuc.ncsa.security.core.Identifier;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration object for RFC 7591 (dynamic client registration) support. This operates
 * at the server level, not as an attribute of a given client.
 * See the <a href="https://cilogon.github.io/oa4mp/server/configuration/client_management-configuration.html">online documentation</a>
 * for details. A simple, global level template is available.
 * <p>Created by Jeff Gaynor<br>
 * on 8/21/21 at  4:58 PM
 */
public class CM7591Config extends CMConfig {
    public CM7591Config() {
    }

    public CM7591Config(String protocol, URI uri, boolean enabled, Identifier template, boolean anonymousOK, boolean autoApprove) {
        super(protocol, uri, enabled);
        this.template = template;
        this.anonymousOK = anonymousOK;
        this.autoApprove = autoApprove;
    }

    public Identifier template = null;
    public boolean anonymousOK = false;
    public boolean autoApprove = false;
    public String autoApproverName = "auto-approved"; // default


    @Override
    public String toString() {
        return "CM7591Config{" +
                "protocol='" + protocol + '\'' +
                ", uri=" + uri +
                ", enabled=" + enabled +
                ", isConfigured=" + isConfigured +
                ", template=" + template +
                ", anonymousOK=" + anonymousOK +
                ", autoApprove=" + autoApprove +
                ", autoApproverName=" + autoApproverName +
                '}';
    }

    /**
     * If this list has any elements, then requests for anonymous clients must originate
     * at one of the domains on this list. Default is a *, which means allow all.
     *
     * @return
     */
    public List<String> getAllowedAnonymousDomains() {
        return allowedAnonymousDomains;
    }

    public void setAllowedAnonymousDomains(List<String> allowedAnonymousDomains) {
        this.allowedAnonymousDomains = allowedAnonymousDomains;
    }

    /**
     * Anonymous client requests from this domain will be auto-approved. The default is that no
     * clients are approved, i.e. it is empty.
     *
     * @return
     */
    public List<String> getAllowedAutoApproveDomains() {
        return allowedAutoApproveDomains;
    }

    public void setAllowedAutoApproveDomains(List<String> allowedAutoApproveDomains) {
        this.allowedAutoApproveDomains = allowedAutoApproveDomains;
    }

    List<String> allowedAnonymousDomains = new ArrayList<>();
    List<String> allowedAutoApproveDomains = new ArrayList<>();

    public boolean checkAnonymousDomain(String host) throws UnknownHostException {
        if (anonymousOK) {
            return checkAllowedDomain(getAllowedAnonymousDomains(), host);
        }
        return false;
    }

    public boolean checkAutoApproveDomain(String host) throws UnknownHostException {
        if (autoApprove) {
            return checkAllowedDomain(getAllowedAutoApproveDomains(), host);
        }
        return false;
    }

    /**
     * returns true if the host is on the allowed list.
     *
     * @param allowedDomains
     * @param host
     * @return
     */
    protected boolean checkAllowedDomain(List<String> allowedDomains, String host) throws UnknownHostException {
        if (allowedDomains.contains("*")) {
            return true;
        }
        // then filter
        boolean gotOne = false;
        for (String x : allowedDomains) {
            InetAddress xxx = InetAddress.getByName(x);
            if (xxx.getHostAddress().equals(host)) {
                return true;
            }
        }
        return false;
    }
}
