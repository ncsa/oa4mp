package org.oa4mp.server.admin.myproxy.oauth2.tools.migrate;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;

import java.util.Date;

import static org.oa4mp.server.admin.myproxy.oauth2.tools.migrate.MigrationConstants.IMPORT_CODE_NOT_DONE;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/25/24 at  7:50 AM
 */
public class MigrationEntry extends IdentifiableImpl {
    public MigrationEntry(Identifier identifier) {
        super(identifier);
    }

    public Date getCreateTS() {
        return create_ts;
    }

    public void setCreateTS(Date create_ts) {
        this.create_ts = create_ts;
    }

    public Date getImportTS() {
        return import_ts;
    }

    public void setImportTS(Date import_ts) {
        this.import_ts = import_ts;
    }

    public String getStoreType() {
        return store_type;
    }

    public void setStoreType(String store_type) {
        this.store_type = store_type.toLowerCase();
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public boolean isImported() {
        return is_imported;
    }

    public void setImported(boolean is_imported) {
        this.is_imported = is_imported;
    }

    public int getImportCode() {
        return importCode;
    }

    public void setImportCode(int importCode) {
        this.importCode = importCode;
    }

    public boolean hasError(){
        return importCode < 0;
    }
    public String getErrorMessage() {
        return error_message;
    }

    public void setErrorMessage(String error_message) {
        this.error_message = error_message;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    Date create_ts = null;

    Date import_ts = null;

    String store_type= null;

    String path      = null;

    boolean is_imported= false;

    int importCode = IMPORT_CODE_NOT_DONE;

    String error_message = null;

    String filename  = null;
}

