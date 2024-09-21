package org.oa4mp.server.qdl;

import org.qdl_lang.workspace.QDLWorkspace;
import org.qdl_lang.workspace.WorkspaceCommands;
import org.qdl_lang.workspace.WorkspaceProvider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/21/24 at  11:19 AM
 */
public class OA4MPQDLWorkspace extends QDLWorkspace {
    public OA4MPQDLWorkspace(WorkspaceCommands workspaceCommands) {
        super(workspaceCommands);
    }

    public static void main(String[] args) throws Throwable {
        WorkspaceProvider workspaceProvider = new QDLOA4MPWorkspaceprovider();
        QDLWorkspace.setWorkspaceProvider(workspaceProvider);
        OA4MPQDLWorkspace workspace = (OA4MPQDLWorkspace) init(args);
        // Fix https://github.com/ncsa/oa4mp/issues/207
        OA2LibLoader2 oa2LibLoader2 = new OA2LibLoader2();
        oa2LibLoader2.add(workspace.getWorkspaceCommands().getState());
        if (workspace != null) {
            workspace.mainLoop();
        }
    }
}
