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

For the Auth Code flow
----------------------
// On your system. Set the environment variable NCSA_DEV_INPUT to point to the
// directory where the QDL scripts live.


// In QDL: Now paste the following in to your workspace, taking care to set users and passwords to your local
// system. DO NOT EXECUTE YET! We're trying to make it so you have the right things in the clipboard
// and don't have to cut and paste a ton of stuff.

script_load(os_env('NCSA_DEV_INPUT')+'/oa4mp/di-service/src/main/scripts/qdl/di_utils.qdl');
di. := {'username':'jeff','password':'woof woof woof','auth_type' : 'simple','service':'https://localhost:9443/oauth2/di'};
cfg.'di' := di.;
resp. := start_af(cfg. );
say('resp.:\n' + print(resp.));
cfg2.'code' := resp.'code';
cfg2.'username' := 'jeff';
cfg2.'di' := di.;
resp2. :=finish_af(cfg2.);
say('resp2:\n' + print(resp2.));
cb_write(resp2.'redirect_uri');
say('redirect_uri is in clipboard:\n' + resp2.'redirect_uri');

//In CLC:  issue the uri command. The URI you want is in the clipboard
// In QDL: Go to the workspace, execute the block of code. This is the entire start then finish
// life cycle. Between the start and finish calls you would have vetted the user and
// finished authenticting them.

//In CLC: execute the grant command (reads the redirect_uri from the clipboard)
// in CLC: issue the access command. You should get tokens and are off and running.

For the Device Code flow
--------------------------
// In the OS: Set NCSA_DEV_INPUT to point to the directory where the QDL scripts live

// In QDL: Copy the next block into your workspace. DO NOT EXECUTE. Again, we
// are trying to set it up so the clipboard does the work.

script_load(os_env('NCSA_DEV_INPUT')+'/oa4mp/di-service/src/main/scripts/qdl/di_utils.qdl');
user_code := tail(to_uri(cb_read()).'query', 'user_code='); // gets the user code
di. := {'username':'jeff','password':'woof woof woof','auth_type' : 'simple','service':'https://localhost:9443/oauth2/di'};
cfg.'di' := di.;
cfg.'user_code' := user_code; // Get user code
resp. := check_user_code(cfg.);
say('resp:\n' + print(resp.));
cfg2.'user_code' := user_code;
cfg2.'username' := 'jeff';
cfg2.'di' := di.;
resp2. := approve(cfg2.);
say('resp2:\n' + print(resp2.));

// In CLC: Issue the df command. This should get a URI and put it in the clipboard
// In QDL: Execute the above code block.
// in CLC: Issue the access command. You should have tokens and be off and running.

End Quickstart for examples
---------------------------

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
