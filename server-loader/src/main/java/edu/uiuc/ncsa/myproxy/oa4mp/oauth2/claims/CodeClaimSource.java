package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.util.StringUtils;

import static edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims.CSConstants.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/8/23 at  12:33 PM
 */
public class CodeClaimSource extends BasicClaimsSourceImpl {
    public CodeClaimSource() {
    }
    public CodeClaimSource(QDLStem stem) {
        super(stem);
      }

    public CodeClaimSource(QDLStem stem, OA2SE oa2SE) {
          super(stem, oa2SE);
        }
    @Override
    public void fromQDL(QDLStem stem) {
        super.fromQDL(stem);
        if(stem.containsKey(CS_CODE_JAVA_CLASS)){
            setClassName(stem.getString(CS_CODE_JAVA_CLASS));
        }
    }

    @Override
    public QDLStem toQDL() {
        QDLStem arg = super.toQDL();
        arg.put(CS_DEFAULT_TYPE, CS_TYPE_CODE);

        if (!StringUtils.isTrivial(getClassName())) {
            arg.put(CS_CODE_JAVA_CLASS, getClassName());
        }
        return arg;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    String className;
}
