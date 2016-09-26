package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;

/**
 * A tool to verify that after a copy, the store contents are identical.
 * <p>Created by Jeff Gaynor<br>
 * on 11/15/13 at  12:33 PM
 */
public class CopyToolVerifier {

    protected CopyTool copyTool;

    /**
     * Override this if you need a different verifier instance. This should just create one.
     *
     * @return
     */
    public CopyTool getCopyTool() {
        if (copyTool == null) {
            copyTool = new CopyTool();
        }
        return copyTool;
    }

    public void doIt(CopyTool adminTool, String[] args) {
        try {
            adminTool.run(args);
        } catch (Throwable e) {
            // uuuugly, but it will work.
            e.printStackTrace();
            say("Error! Could not copy store. Verificatiohn aborted.");
            return;
        }
        say("Preparing to check stores.");
        try {
            if (verifyStores(adminTool.getSourceEnv(), adminTool.getTargetEnv())) {
                say("Done! All checks passed.");
            }
            // note that a failure will be reported by the verifyStore call and print out some diagnostics.
        } catch (Throwable t) {
            say("There was an exception encountered while trying to process this. Check the copy logs for more information");
            adminTool.getMyLogger().error("Error verifying copy!", t);
        }

    }

    public static void main(String[] args) {
        CopyToolVerifier cctv = new CopyToolVerifier();
        if (args == null || args.length == 0) {
            cctv.printHelp();
            return;
        }
        cctv.doIt(cctv.getCopyTool(), args);
    }

    public void printHelp() {
        say("OA4MP copy tool verifier.");
        say("\njava -jar oa4mp-cp-verifier [args]\n");
        say("Where the arguments are identical to what you would supply in the copy tool.");
        say("This tool will execute a full copy of the source store to the target store.");
        say("It will then check that each copied store is identical to the source.");
        say("This is designed to be a complete and low-level check that looks at *every*");
        say("single entry in both stores and compares them. It is therefore not designed to be a standard tool");
        say("but is useful mostly for debugging the copy tool. You could also use it to ");
        say("copy a store to a file store or memory store to check that the copy tool works.");
        say("For large stores this is very slow and you should have a good reason for running this tool...");
    }

    /**
     * Run through all the stores in these environments. Call super when overriding this method.
     *
     * @param sEnv
     * @param tEnv
     * @return
     */
    public boolean verifyStores(ServiceEnvironmentImpl sEnv, ServiceEnvironmentImpl tEnv) {
        if (!verifyStore("clients", sEnv.getClientStore(), tEnv.getClientStore())) return false;
        if (!verifyStore("client approvals", sEnv.getClientApprovalStore(), tEnv.getClientApprovalStore()))
            return false;
        return true;
    }

    public boolean verifyStore(String storeName, Store<? extends Identifiable> source, Store<? extends Identifiable> target) {
        long srcSize = source.size();
        if (srcSize != target.size()) {
            say("Error: Source \"" + source + "\"(" + srcSize + ") and target \"" + target + "\"(" + target.size() + ") are not the same");
            return false;
        }
        saynoCR("Checking store " + storeName + " with " + srcSize + " elements... ");
        for (Identifier identifier : source.keySet()) {
            if (!target.containsKey(identifier)) {
                say("Error: Source store contains key " + "\"" + identifier + "\" and target store does not.");
                return false;
            }
            Identifiable src = source.get(identifier);
            if (src == null) {
                say("Error: Failed getting source object with identifier \"" + identifier + "\"");
                return false;
            }
            Identifiable trgt = target.get(identifier);

            if (trgt == null) {
                say("Error: Failed getting target object with identifier \"" + identifier + "\"");
                return false;
            }

            if (!src.equals(trgt)) {
                say("Error: source and target objects do not match!");
                say("Source object:\n\n" + src.toString());
                say("\nTarget object:\n\n" + trgt.toString());
                return false;
            }
        }

        say("ok!");
        return true;
    }


    public void say(String x) {
        System.out.println(x);
    }

    public void saynoCR(String x) {
        System.out.print(x);
    }

}
