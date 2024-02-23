/*
   This comment section tells how to set up an Apache Derby database to
   work with OA4MP.

   Create the directory to where you want derby to create the database.
   This directory should be empty, since Derby will create everything on your
   behalf -- and might refuse to do anything if the directory has content.
   Make the following substitutions below:

         DB_NAME - the entire path to this database,
     DB_PASSWORD - password to the database
       USER_NAME - name of the user (created below)
   USER_PASSWORD - password for user
          SCHEMA - schema for the database

   Note 1: If you want your database to live in

       /opt/oauth2/var/derby/oa4mp

   you would create

      /opt/oauth2/var/derby

   with nothing in it and the DB_NAME is then

      /opt/oauth2/var/derby/oa4mp

   I.e., the last directory in this path is what Derby creates.

   Note 2: In Derby, the database lives in a directory. This means that unless
   certain precautions are taken, it is completely insecure. The setup below
   mitigates this.

   1. Puts a password on the entire database so it cannot be read from the disk
   2. Sets a user and password to access the database.
      These are stored in the database, hence step 1 to lock the whole thing down.
   3. All database access from OA4MP is via the so-called embedded driver, so
      no network traffic is needed.

   One-time install instructions
   ----------------------------
   Install derby, probably with a package manager like synaptic or yum.
   Note that outdented lines are to be pasted into the command line

   Start derby with

ij

   Then issue the following. This sets up the database and will create the user above
   (Note that the user name and password are set as properties, so do substitute).
   Even though the user does not exist yet, you must  connect with the
   user name so that they are the owner of the database.

connect 'jdbc:derby:DB_NAME;create=true;dataEncryption=true;bootPassword=DB_PASSWORD;user=USER_NAME';
call syscs_util.syscs_set_database_property('derby.connection.requireAuthentication', 'true');
call syscs_util.syscs_set_database_property('derby.authentication.provider', 'BUILTIN');
call syscs_util.syscs_set_database_property('derby.user.USER_NAME', 'USER_PASSWORD');
call syscs_util.syscs_set_database_property('derby.database.propertiesOnly', 'true');
call syscs_util.syscs_set_database_property('derby.database.sqlAuthorization', 'true');

   Optional test:
   If you want be sure it works, create the schema as follows:

create schema oauth2;
show schemas;

   And a bunch of schemas will be displayed, including oauth2. This means everything
   worked. You don't need to issue the create schema command below.

   At this point, exit Derby. Initial setup is done. You must connect again as the user
   that runs this because creating the tables below will automatically assign the
   current user as the table owner, so no other permissions (which can get complicated)
   are needed.

exit;

   Now connect to it with the following from the command line after restarting ij:

connect 'jdbc:derby:DB_NAME;user=USER_NAME;password=USER_PASSWORD;bootPassword=DB_PASSWORD';

   and either paste in the rest of this file OR just run the whole thing from inside ij

run '/full/path/to/oauth2-derby.qdl';

   At this point, your database is ready for use.

  If you need to see what columns a table has use the describe command, e.g.

   describe oauth2.clients;

   connect 'jdbc:derby:memory:xxx;create=true';
   ij> create schema oauth2;


*/
