package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfiguration;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

/**
 * A claim source backed by a file system. The file simply contains a JSON object of userids and attributes
 * associated with that id. These are then returned as claims.
 * <p>Created by Jeff Gaynor<br>
 * on 10/21/19 at  12:49 PM
 */
public class FSClaimSource extends BasicClaimsSourceImpl {
    public FSClaimSource(ClaimSourceConfiguration config) {
        setConfiguration(config);
    }

    /**
     * The name of the property in the configuration that specifies where the file is that holds
     * the claims for this source.
     */
    public static String FILE_PATH_KEY = "filePath";

    /*
    The test file contains a JSON object of properties, e.g. of the form
    {"userid123":{"foo":"bar","eppn":"fnord@blarg.edu"}}
    In this case, there is exactly one entry for the user with username "userid123" and the two claims
    will be included in the claims object.
     */
    @Override
    protected JSONObject realProcessing(JSONObject claims, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        Object rawfilePath = getConfiguration().getProperty(FILE_PATH_KEY);
        if (rawfilePath == null) {
            throw new GeneralException("ERROR:No \"" + FILE_PATH_KEY + "\" set for this claim source.");
        }
        String filePath = rawfilePath.toString();
        if (filePath.isEmpty()) {
            throw new GeneralException("ERROR:No \"" + FILE_PATH_KEY + "\" set for this claim source.");
        }

        File f = new File(filePath);
        if (!f.exists()) {
            throw new GeneralException("ERROR:File \"" + f + "\" does not exist on this system.");
        }
        if (!f.isFile()) {
            throw new GeneralException("ERROR: \"" + f + "\" is not a file.");
        }
        if (!f.canRead()) {
            throw new GeneralException("ERROR: \"" + f + "\" cannot be read.");
        }
        // Finally, we can do something...
        String rawJSON = null;
        try {
            rawJSON = readFile(filePath);
        } catch (IOException e) {
            DebugUtil.error(this, "Error reading file \"" + e.getMessage() + "\".", e);
            throw new GeneralException(e);
        }
        JSONObject jsonObject = JSONObject.fromObject(rawJSON);
        JSONObject json = jsonObject.getJSONObject(transaction.getUsername());
        claims.putAll(json);
        return super.realProcessing(claims, request, transaction);
    }

    protected String readFile(String path) throws IOException {
        File file = new File(path);
        FileReader fileReader = new FileReader(file);
        BufferedReader bufferedReader = new BufferedReader(fileReader);
        StringBuffer lines = new StringBuffer();
        String inLine = bufferedReader.readLine();
        while (inLine != null) {
            lines.append(inLine + "\n");
            inLine = bufferedReader.readLine();
        }
        bufferedReader.close();
        return lines.toString();
    }

    @Override
    public boolean isRunAtAuthorization() {
        return false; // run this only when access tokens are being created, not in the authorization step.
    }
}
