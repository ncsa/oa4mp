package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/4/12 at  11:28 AM
 */
public class AuthorizationServletConfig {
    public AuthorizationServletConfig(boolean useHeader,
                                      boolean requireHeader,
                                      String headerFieldName,
                                      boolean returnDnAsUsername,
                                      boolean showLogon,
                                      boolean verifyUsername,
                                      boolean convertDNToGlobusID) {
        this.headerFieldName = headerFieldName;
        this.requireHeader = requireHeader;
        this.useHeader = useHeader;
        this.returnDnAsUsername = returnDnAsUsername;
        this.showLogon = showLogon;
        this.verifyUsername = verifyUsername;
        this.convertDNToGlobusID = convertDNToGlobusID;
    }

    boolean showLogon;

    public boolean isVerifyUsername() {
        return verifyUsername;
    }

    public void setVerifyUsername(boolean verifyUsername) {
        this.verifyUsername = verifyUsername;
    }

    public boolean isShowLogon() {
        return showLogon;
    }

    public void setShowLogon(boolean showLogon) {
        this.showLogon = showLogon;
    }

    boolean verifyUsername;
    boolean useHeader;
    boolean requireHeader;
    String headerFieldName;
    boolean returnDnAsUsername;

    public boolean isConvertDNToGlobusID() {
        return convertDNToGlobusID;
    }

    public void setConvertDNToGlobusID(boolean convertDNToGlobusID) {
        this.convertDNToGlobusID = convertDNToGlobusID;
    }

    boolean convertDNToGlobusID;

    public boolean isReturnDnAsUsername() {
        return returnDnAsUsername;
    }

    public String getHeaderFieldName() {
        return headerFieldName;
    }

    public boolean isRequireHeader() {
        return requireHeader;
    }

    public boolean isUseHeader() {
        return useHeader;
    }
}
