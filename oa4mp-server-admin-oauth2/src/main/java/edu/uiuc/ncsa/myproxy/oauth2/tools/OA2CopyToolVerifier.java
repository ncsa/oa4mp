package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.server.CopyTool;
import edu.uiuc.ncsa.myproxy.oa4mp.server.CopyToolVerifier;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  1:30 PM
 */
public class OA2CopyToolVerifier extends CopyToolVerifier {

    @Override
    public CopyTool getCopyTool() {
        if (copyTool == null) {
            copyTool = new OA2CopyTool();
        }
        return copyTool;
    }

    public static void main(String[] args) {
           OA2CopyToolVerifier cctv = new OA2CopyToolVerifier();
           if (args == null || args.length == 0) {
               cctv.printHelp();
               return;
           }
           cctv.doIt(cctv.getCopyTool(), args);
       }

}
