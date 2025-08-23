package org.oa4mp.di;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/7/22 at  2:00 PM
 */
public class Err {
    public Err(int code,
               String error,
               String description,
               URI errorURI,
               URI customErrorURI) {
        this(code, error, description);
        this.errorURI = errorURI;
        this.customErrorURI = customErrorURI;
    }

    public Err(int code, String error, String description) {
        this.code = code;
        this.error = error;
        this.description = description;
    }

   public int code;
   public String description;
   public String error;
   public URI errorURI = null;
   public URI customErrorURI = null;
}
