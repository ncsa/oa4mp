This directory contains QDL scripts to use the Detached/Independent (DI)  service. The scripts may be
called individually (run di_utils.qdl first to load a bunch of helper functions).

+-----------------------+
|  Testing  Quickstart  |
+-----------------------+

╔═══════════════════════════════════════════════╗
║    Be sure to change the web.xml to use       ║
║    the DIService and update the server config ║
║    accordingly!!                              ║
╚═══════════════════════════════════════════════╝



These let you be an Authorization Server from the command line easily. Useful for e.g. testing.

This is designed to work as a library to QDL, to wit, in a workspace,
you set the lib path and enable library_support
then all the scripts become functions in the workspace, so you can call them directly, e.g.

to run start_af.qdl with arguments cfg. and uri, just issue

start_af(cfg., uri)

(equivalent to issuing
   script_path('/path/to/scripts' ~ script_path();
   script_load('start_af.qdl', cfg., uri)
but a lot less typing and importing.)

and the system will find the script and run it as if it were an imported function. The library
facility in QDL lets you write some very complex scripting and use it easily.

Data structures
---------------
The di server requires a configuration with the endpoint, and authorization information. This is in
the configuration stem as the element di, so a typical use might be

di. := {'username':'bob',
        'password':'Oh sphinx of black onyx!',
        'auth_type' : 'simple',
        'service':'https://localhost:9443/oauth2/di'
        };
cfg.'di' := di.;
cfg.'auth_time' := date_ms()%1000; // now, in seconds
...

then add any other configuration entries.

The Authorization Code Flow
---------------------------
start_af.qdl - Before any authentication is done, passes along the reuqest string
               E.g. from the CLC's uri command. Creates a transaction and returns
               the code aka auth grant
finish_af.qdl - After authentication, notify OA4MP that it was successful and send
                the user's name and auth time.

OA4MP does not care how the user is authenticated, and has no access to any backing
user management system. For testing, just run them sequentially.

The Device Code Flow
---------------------------
In the Device Code Flow (DCF) the client makes a request to the service, which is configured
to return the URL that points to their AS as the verification server. The two functions are

check_user.qdl - checks if the user's code is still valid
approve.qdl - informs OA4MP that the user has either successfully authenticated or haa cancelled the flow.
