/*
   Table for migration utility. This allows an administrator to take a fileStore and import
   it into another store. The issue is that if teh file store is huge, doing that with
   the copy utility is probably going to crash. This does it the Right Way.

   It is a derby store because we can just create one on the fly and use it.

 */
CREATE TABLE oa4mp.ingest
(
   create_ts              timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
   import_ts              timestamp,
   identifier             varchar(255),
   store_type             varchar(255),
   path                   clob,
   is_imported            boolean,
   import_code            int,
   error_message          clob,
   filename               VARCHAR(255),
   description            VARCHAR(255),
   PRIMARY KEY (filename, store_type)
);

