package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.qdl.workspace.QDLWorkspace;
import edu.uiuc.ncsa.qdl.workspace.WorkspaceCommands;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/21/24 at  11:19 AM
 */
public class OA4MPQDLWorkspace extends QDLWorkspace {
    public OA4MPQDLWorkspace(WorkspaceCommands workspaceCommands) {
        super(workspaceCommands);
    }

    public static void main(String[] args) throws Throwable {
        OA4MPQDLWorkspaceCommands.setInstance(new OA4MPQDLWorkspaceCommands());
        init(args);
    }
}
