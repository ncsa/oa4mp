package org.oa4mp.delegation.server.server;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/9/21 at  11:22 AM
 */
public interface RFC8628Constants {
    String GRANT_TYPE_DEVICE_CODE = RFC8693Constants.IETF_CAPUT + "oauth:grant-type:device_code";
    /**
     * REQUIRED.  The device verification code.
     */
    String DEVICE_CODE = "device_code";

    /**
     * REQUIRED.  The end-user verification code.
     */
    String USER_CODE = "user_code";
    /**
     * REQUIRED.  The end-user verification URI on the authorization
     * server.  The URI should be short and easy to remember as end users
     * will be asked to manually type it into their user agent.
     */
    String VERIFICATION_URI = "verification_uri";
    String VERIFICATION_URI_ENDPOINT = "device";
    String DEVICE_AUTHORIZATION_ENDPOINT = "device_authorization";


    /**
     * OPTIONAL.  A verification URI that includes the "user_code" (or
     * other information with the same function as the "user_code"),
     * which is designed for non-textual transmission.
     */
    String VERIFICATION_URI_COMPLETE = "verification_uri_complete";
    /**
     * REQUIRED.  The lifetime in seconds of the "device_code" and
     * "user_code".
     */
    String EXPIRES_IN = "expires_in";
    /**
     * OPTIONAL.  The minimum amount of time in seconds that the client
     * SHOULD wait between polling requests to the token endpoint.  If no
     * value is provided, clients MUST use 5 as the default.
     */
    String INTERVAL = "interval";
    /**
     * Characters to be used in user codes. This is almost basic ascii except for characters
     * that are confused. So there is zero, but no lower/uppercase "oh". Similar no lower case
     * "L" which looks like a 1 in a lot of fonts.
     */
    // next is if you want lower case as well
    //char[] CODE_CHARS="0123456789ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz".toCharArray();
    // next has upper case vowels in it.
    //char[] CODE_CHARS="0123456789ABCDEFGHIJKLMNPQRSTUVWXYZ".toCharArray();
    //char[] CODE_CHARS = "0123456789CDFGHJKLMNPQRTVWXZ".toCharArray();
    // After a lot of discussions, this was decided upon. Might want this to be configurable???
   char[] CODE_CHARS = "234679CDFGHJKLMNPQRTVWXZ".toCharArray();

    /**
     * Number of characters in a user code.
     * So if this is 6, then a user code of ABC_DEF (6 actual characters, exclusive of separator)
     * will be created. To be safe, 8*USER_CODE_DEFAULT_LENGTH is the number of bytes created,
     * since how many we need is based on the number of CODE_CHARS and it gets murky fast how to
     * exactly compute the number of bytes. T
     */
     int USER_CODE_DEFAULT_LENGTH = 9;
    /**
     * Used between sets of 4 characters in the user code for readability
     */
     char USER_CODE_SEPERATOR_CHAR = '-';

    /**
     * Number of milliseconds that we wait between calls to create a new user code.
     * Spec suggests 5 seconds.
     */
     long DEFAULT_WAIT = 5000;

     int USER_CODE_PERIOD_LENGTH = 3;

}
