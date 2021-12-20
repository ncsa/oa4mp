package test;

import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.qdl.TestUtils;
import edu.uiuc.ncsa.qdl.evaluate.MetaEvaluator;
import edu.uiuc.ncsa.qdl.evaluate.OpEvaluator;
import edu.uiuc.ncsa.qdl.functions.FStack;
import edu.uiuc.ncsa.qdl.module.MAliases;
import edu.uiuc.ncsa.qdl.module.MTemplates;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.state.SymbolStack;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/13/21 at  6:44 AM
 */
public class QDLTestUtils extends TestUtils {

    @Override
    public State createStateObject(MAliases mAliases,
                                   SymbolStack symbolStack,
                                   OpEvaluator opEvaluator,
                                   MetaEvaluator metaEvaluator,
                                   FStack fStack,
                                   MTemplates mTemplates,
                                   MyLoggingFacade myLoggingFacade,
                                   boolean isServerMode,
                                   boolean assertionsOn) {
        return new OA2State(new MAliases(),
                symbolStack,
                new OpEvaluator(),
                MetaEvaluator.getInstance(),
                new FStack(),
                new MTemplates(),
                null,
                false,
                false,
                true,
                true,
                null);
    }

    // A main method for testing snippets of code.
    public static void main(String[] args) {
        try {
            Class.forName("org.apache.derby.jdbc.EmbeddedDriver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
