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
        WorkspaceCommands.setWorkspaceCommandsProvider(new QDLOA4MPWorkspaceCommandsProvider());
        OA4MPQDLWorkspace workspace = (OA4MPQDLWorkspace) init(args);
        if (workspace != null) {
            workspace.mainLoop();
        }
    }



}
