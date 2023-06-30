package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/4/12 at  11:28 AM
 */
public class AuthorizationServletConfig {
    /**
     * Constructor if a proxy is to be used for authorization. This points to a file
     * with the configuration in it and the name of the configuration to use.
     * @param cfgFile
     * @param cfgName
     */
    public AuthorizationServletConfig(String cfgFile, String cfgName){
        this.cfgFile = cfgFile;
        this.cfgName = cfgName;
        setUseProxy(true);
    }

    public AuthorizationServletConfig(String authorizationURI,
                                      boolean useHeader,
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
        this.authorizationURI = authorizationURI;
        setUseProxy(false);
    }

    public boolean isUseProxy() {
        return useProxy;
    }

    public void setUseProxy(boolean useProxy) {
        this.useProxy = useProxy;
    }

    public String getCfgFile() {
        return cfgFile;
    }

    public void setCfgFile(String cfgFile) {
        this.cfgFile = cfgFile;
    }

    public String getCfgName() {
        return cfgName;
    }

    public void setCfgName(String cfgName) {
        this.cfgName = cfgName;
    }

    boolean useProxy = false;
    String cfgFile = null;
    String cfgName = null;

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

    public String getAuthorizationURI() {
        return authorizationURI;
    }

    public void setAuthorizationURI(String authorizationURI) {
        this.authorizationURI = authorizationURI;
    }

    String authorizationURI;

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

    @Override
    public String toString() {
        return "AuthorizationServletConfig{" +
                "useProxy=" + useProxy +
                ", cfgFile='" + cfgFile + '\'' +
                ", cfgName='" + cfgName + '\'' +
                ", showLogon=" + showLogon +
                ", verifyUsername=" + verifyUsername +
                ", useHeader=" + useHeader +
                ", requireHeader=" + requireHeader +
                ", headerFieldName='" + headerFieldName + '\'' +
                ", returnDnAsUsername=" + returnDnAsUsername +
                ", authorizationURI='" + authorizationURI + '\'' +
                ", convertDNToGlobusID=" + convertDNToGlobusID +
                '}';
    }
}
