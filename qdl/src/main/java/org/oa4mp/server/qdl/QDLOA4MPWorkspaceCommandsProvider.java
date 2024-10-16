package org.oa4mp.server.qdl;

import edu.uiuc.ncsa.security.util.cli.IOInterface;
import org.qdl_lang.workspace.WorkspaceCommands;
import org.qdl_lang.workspace.WorkspaceCommandsProvider;

public class QDLOA4MPWorkspaceCommandsProvider extends WorkspaceCommandsProvider {
    @Override
    public WorkspaceCommands get() {
        return new OA4MPQDLWorkspaceCommands();
    }

    @Override
    public WorkspaceCommands get(IOInterface ioInterface) {
        return new OA4MPQDLWorkspaceCommands(ioInterface);
    }
}
