A MUCH fuller version of this
is at https://docs.google.com/document/d/1GmacW2R7IffZlgTpEMZAqRQsW139xwwplHSgS3hX-1s/edit?usp=sharing)

This directory contains scripts that will generate various things for signed JWT (ok, JWT = JSON Web Tokens,
but everyone now wrongly calls them ID Tokens).

Abbreviations
JWT = Java Web Token conforms to RFC 7519: https://tools.ietf.org/html/rfc7519
JWK = Java Web Key conforms to RFC 7517: https://tools.ietf.org/html/rfc7517

** Setting shell variables first

Before running the scripts, you should set the environment by running the set-evn.sh script (typically using the source
command):

 source ./set-env.sh

 Basically you just need to point java at the jar to invoke. If you got this as a tarball, then it should all just work from the
 untarred directory. You only need to set the environment once in your session.

** Running the interpreter interactively

Just invoke

java -jar jwt.jar

and you will be prompted for commands. There is a startup banner with a lot of information.  The prompt looks like

jwks>

You can get help by passing in --help, e.g.

jwks>--help

(Lots of stuff prints)

This includes all the commands so if you want get the help on a command, e.g. echo you would enter

jwks>echo --help

echo arg0 arg1...
   Simply echos the arg(s) to the console . This is extremely useful in scripts.



** Basic Scripts

These are bash scripts that allow you to execute single commands, such as creating keys and so forth.

Read the help for each of the following. You can invoke detailed help by invoking the script with the --help flag.
E.g.

./create_keys.sh --help


Note that this invokes a much larger library and the help talks about interactive mode and batch mode. These scripts
all run in batch mode. 

create_keys.sh = creates a set of standard RSA keys (both public and private parts) at various strengths.
   Output is JSON Web Key format.
create_symmetric_keys.sh = creates a set of symmetric keys
create_token.sh = takes a token and simply creates the signature -- no claims added.
generate_token = takes a set of claims and adds all of the standard expirations, possibly a JTI and so forth.
log.sh = prints out the tail of the current log file.
print_token.sh  = prints the header and payload of a token. No validation or other checking is done.
validate_token.sh = takes a token and key and verifies the signature.


run.sh = run any command in batch mode. For instance

$SCRIPT_PATH/run.sh echo foo!

foo!


** Batch files

The processor also has the ability to run batches of commands found in a single file. The syntax of the file
is designed to be as minimal as possible:

* a line that starts with a hash (#) is a comment and is ignored at run time
* Commands may span many lines with as much whitespace as you like, but the end of command marker is a
  semi-colon (;) and as soon as that is found, the command will execute. Note that all lines will be
  put into a single line with a single space between each by the command preprocessor.

Example.

So to print out a sample signed JWT you would issue

./run-cmd.sh ex_print_token.cmd

and a sample would be printed. The first command (run-cmd.sh) will fire up the interpreter and pass in the
file to it, then the interpreter will run the file. In this case a header and payload from a supplied token
would be printed.


** Environment variables.

The command processor has any number of features including the ability to have an environment set either as a
Java properties file or as a JSON object. The distro contains two examples

test_env.props
more_props.json

How do these work? The key/value pairs are read in and the you simple use ${key} wherever you want.
Note that the substitutions happen before any processing of the command line, so you can literally
replace anything you want, including command line switches.

For instance, if your properties file consists of the single line

kid=ABC123

Then the following command

generate_keys -kid ${kid} -jti...

would become

generate_keys -kid ABC123 -jti ...

and then get passed to the interpreter. Note that there is no checking of any sort done -- it is just a straight up
string substitution, so you can have something like MYKEY${kid}456 ---> MYKEYABC123456 for instance.

You can import environment variables in interactive mode and in batch files. Batch mode is still not supported though
that may change. At this point, you must pass in all parameters directly. 

Here is an example to show how to use environment variables with a command file.
This will write the properties to the console so you can see that it works:

ex_env.cmd

Invoke

./run-cmd.sh ex_env.cmd

to run the command file (a file containing a set of commands).

