package org.oa4mp.server.loader.oauth2.claims;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.qdl_lang.variables.QDLStem;

import static org.oa4mp.server.loader.qdl.claims.CSConstants.*;

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
        QDLStem stem = super.toQDL();
        addToStem(stem,CS_DEFAULT_TYPE, CS_TYPE_CODE);
        addToStem(stem,CS_CODE_JAVA_CLASS, getClassName());
        return stem;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    String className;
}
