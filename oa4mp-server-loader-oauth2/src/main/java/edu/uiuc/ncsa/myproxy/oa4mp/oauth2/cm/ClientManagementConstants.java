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
 * In this case, the RFC 7519 endpoint is completely specified. In the other 2 cases, it will be
 * constructed from the server's address (found in the environment's {@link OA2SE#getServiceAddress()}
 * property). In this case, the native OA4MP client management endpoint has been disabled.
 * <p>Created by Jeff Gaynor<br>
 * on 7/25/19 at  11:01 AM
 */
public interface ClientManagementConstants {
    public String CLIENT_MANAGEMENT_TAG = "clientManagement";
    public String API_TAG = "api";
    public String DEFAULT_RFC7591_ENDPOINT = "oidc-cm";
    public String DEFAULT_OA4MP_ENDPOINT = "clients" +
            "";
    public String ENABLED_ATTRIBUTE="enabled";

    // protocol values
    public String PROTOCOL_ATTRIBUTE = "protocol";
    public String RFC_7591_VALUE = "rfc7591";
    public String RFC_7592_VALUE = "rfc7592";
    public String OA4MP_VALUE = "oa4mp";

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
