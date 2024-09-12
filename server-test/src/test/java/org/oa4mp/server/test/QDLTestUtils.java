package org.oa4mp.server.test;

import org.oa4mp.server.loader.qdl.scripting.OA2State;
import org.qdl_lang.TestUtils;
import org.qdl_lang.evaluate.MetaEvaluator;
import org.qdl_lang.evaluate.OpEvaluator;
import org.qdl_lang.functions.FStack;
import org.qdl_lang.module.MIStack;
import org.qdl_lang.module.MTStack;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.VStack;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/13/21 at  6:44 AM
 */
public class QDLTestUtils extends TestUtils {

    @Override
    public State createStateObject(
                                   VStack vStack,
                                   OpEvaluator opEvaluator,
                                   MetaEvaluator metaEvaluator,
                                   FStack fStack,
                                   MTStack mTemplates,
                                   MIStack mInstance,
                                   MyLoggingFacade myLoggingFacade,
                                   boolean isServerMode,
                                   boolean assertionsOn) {
        return new OA2State(
                vStack,
                new OpEvaluator(),
                MetaEvaluator.getInstance(),
                new FStack(),
                new MTStack(),
                new MIStack(),
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
