package edu.uiuc.ncsa.myproxy.oa4mp.server;

/**
 * Provider standard keys for the service.
 * <p>Created by Jeff Gaynor<br>
 * on 4/30/12 at  10:59 AM
 */
public interface ServiceConstantKeys {
    public static final String CALLBACK_URI_KEY = "oa4mp:callback_uri";
    public static final String TOKEN_KEY = "oa4mp:token";
    public static final String FORM_ENCODING_KEY = "oa4mp:form_encoding"; //usually UTF-8...
    public static final String CERT_REQUEST_KEY = "oa4mp:certreq";
    public static final String CERT_LIFETIME_KEY = "oa4mp:certlifetime";
    public static final String CONSUMER_KEY = "oa4mp:client_id";

}
