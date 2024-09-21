package org.oa4mp.server.qdl;

import org.qdl_lang.workspace.QDLWorkspace;
import org.qdl_lang.workspace.WorkspaceCommands;
import org.qdl_lang.workspace.WorkspaceProvider;

public class QDLOA4MPWorkspaceprovider implements WorkspaceProvider {
    @Override
    public QDLWorkspace getWorkspace(WorkspaceCommands workspaceCommands) {
        return new OA4MPQDLWorkspace(workspaceCommands);
    }
}
