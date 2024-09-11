package org.oa4mp.server.qdl;

import org.qdl_lang.workspace.QDLWorkspace;
import org.qdl_lang.workspace.WorkspaceCommands;

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
