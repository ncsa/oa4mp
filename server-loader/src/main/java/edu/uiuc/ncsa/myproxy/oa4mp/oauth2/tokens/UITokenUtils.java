package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2HeaderUtils;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenFactory;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Errors;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2GeneralError;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;

import static edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants.ACCESS_TOKEN;

/**
 * Mostly this is used in the {@link edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.UserInfoServlet}
 * where the handling has to be a bit different than in the token endpoint.
 * <p>Created by Jeff Gaynor<br>
 * on 5/3/21 at  4:02 PM
 */
public class UITokenUtils {
    /**
     * Given a string of some token (unknown format, e.g. from a header or
     * passed in as a parameter) return an access token.<br/><br/>
     * <b>Note</b> this does not verify the token if it's a JWT! This is because one usage
     * pattern for {@link edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VirtualOrganization} is to get the token,
     * find the transaction, read the client, then determine the VO and check the keys.
     * This call lets you bootstrap that process. Note that at this point in the flow we cannot
     * check the signature.
     *
     * @param rawAT
     * @return
     */
    public static AccessTokenImpl getAT(String rawAT) {
        return TokenFactory.createAT(rawAT);
    }

    public static RefreshTokenImpl getRT(String rawRT) {
        return TokenFactory.createRT(rawRT);
    }


    /**
     * Gets the current raw access token from either  the header or as a parameter. This throws an exception none is found.
     * Pass the result off to {@link #getAT(String)} to ferret out the actual
     * @param request
     * @return
     */
    public static String getRawAT(HttpServletRequest request) {
        String headerAT = OA2HeaderUtils.getBearerAuthHeader(request);
        String paramAT = request.getParameter(ACCESS_TOKEN);
        //String paramAT = getFirstParameterValue(request, ACCESS_TOKEN);
        if(headerAT == null && paramAT == null){
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                            "missing access token",
                            HttpStatus.SC_BAD_REQUEST,
                            null);
        }

        return headerAT == null?paramAT:headerAT;
    }
}
