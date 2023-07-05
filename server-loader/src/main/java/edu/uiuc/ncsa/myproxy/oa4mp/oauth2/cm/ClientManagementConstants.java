package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;

/**
 * These are constants for the configuration of the client management facilities.
 * A typical set of entries might look like
 * <pre>
 *     &lt;clientManagement&gt;
 *         &lt;api protocol="rfc7951" enabled="true"  url="https://foo.bar/oauth2/rfc77591"/&gt;
 *         &lt;api protocol="rfc7952" enabled="true" endpoint="oidc-cm2" /&gt;
 *         &lt;api protocol="oa4mp" enabled="false" endpoint="oidc-cm" "/&gt;
 *     &lt;/clientManagement&gt;
 * </pre>
 * In this case, the RFC 7591 endpoint is completely specified. In the other 2 cases, it will be
 * constructed from the server's address (found in the environment's {@link OA2SE#getServiceAddress()}
 * property). In this case, the native OA4MP client management endpoint has been disabled.
 * <p>Created by Jeff Gaynor<br>
 * on 7/25/19 at  11:01 AM
 */
public interface ClientManagementConstants {
    public String CLIENT_MANAGEMENT_TAG = "clientManagement";
    // The next are attributes of this tag.
    /**
     * Client id of a configured client to use as a template.
     */
    public String RFC_7591_TEMPLATE = "template";

    public String API_TAG = "api";
    public String DEFAULT_RFC7591_ENDPOINT = "oidc-cm";
    public String DEFAULT_OA4MP_ENDPOINT = "clients";
    public String ENABLE_SERVICE="enabled";

    // protocol values
    public String PROTOCOL_ATTRIBUTE = "protocol";
    public String RFC_7591_VALUE = "rfc7591";
    public String RFC_7592_VALUE = "rfc7592";
    public String OA4MP_VALUE = "oa4mp";

    /**
     * Whether or not to automatically approve anonymous requests. This <b><i>may</i></b> happen
     * in highly automated systems with severely restricted access. Generally though setting
     * it true is a terrible idea and a security risk.
     */
    public String RFC_7591_AUTO_APPROVE = "autoApprove";
    public String RFC_7591_AUTO_APPROVE_ALLOWED_DOMAINS = "autoApproveAllowedDomains";

    public String RFC_7591_AUTO_APPROVER_NAME = "autoApproverName";
    /**
     * Allow anonymous create for this endpoint for a client. This means that a post with
     * client information to this endpoint will be allowed and an <i>unapproved</i>
     * client  will result.
     */
    public String RFC_7591_ANONYMOUS_OK = "anonymousOK";
    public String RFC_7591_ANONYMOUS_ALLOWED_DOMAINS = "anonymousAllowedDomains";

    /**
     * If the protocol is to be derived from the server address, just set the endpoint,
     * e.g. if the server address is <code>https://foo.bar/oauth2</code>
     * and the endpoint is <code>register</code>
     * then the resulting client registration endpoint would be
     * <code>https://foo.bar/oauth2/register</code>
     */
    public String ENDPOINT_ATTRIBUTE= "endpoint";
    /**
     * Specify the complete url for the client registration endpoint. Note that this will
     * only affect the RFC7951 and RFC7952 protocols and will override the endpoint tag.
     * Use this if, e.g., the registration servlet is located on a completely different machine
     * than the OA4MP server, or if there is some other reason to do so.
     */
    public String FULL_URL_ATTRIBUTE = "url";
}
