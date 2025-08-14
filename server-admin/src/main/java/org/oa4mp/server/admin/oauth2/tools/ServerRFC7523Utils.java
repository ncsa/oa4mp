package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import net.sf.json.JSONObject;
import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.server.OA2Constants;
import org.oa4mp.delegation.server.client.RFC7523Utils;
import org.oa4mp.delegation.server.jwt.MyOtherJWTUtil2;

import java.net.URI;
import java.util.Map;

/**
 * Supports starting a flow with an admin client.
 */
public class ServerRFC7523Utils extends RFC7523Utils {


}
