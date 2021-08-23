package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm;

import edu.uiuc.ncsa.security.core.Identifier;

import java.net.URI;

/**
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
}
