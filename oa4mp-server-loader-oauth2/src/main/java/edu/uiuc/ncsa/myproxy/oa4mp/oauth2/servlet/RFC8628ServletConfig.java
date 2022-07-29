package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC8628Constants;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/14/21 at  8:59 AM
 */
public class RFC8628ServletConfig implements RFC8628Constants{
   public String deviceEndpoint;
   public String deviceAuthorizationEndpoint;
   public long lifetime = -1L;

    public long interval = DEFAULT_WAIT;
    // For later -- make a bunch more stuff configurable, such as the code chars, length etc/
    // This will require some little retooling of the servlet:
   public char[] codeChars = CODE_CHARS;

    /**
     * Number of bytes in a user code.
     */
    public int userCodeLength = USER_CODE_DEFAULT_LENGTH;
    /**
     * Used between sets of 4 characters in the user code for readability
     */
    public String userCodeSeperator = ""+USER_CODE_SEPERATOR_CHAR;

    /**
     * Number of milliseconds that we wait between calls to create a new user code.
     * Spec suggests 5 seconds.
     */

    public int userCodePeriodLength = USER_CODE_PERIOD_LENGTH;
}
