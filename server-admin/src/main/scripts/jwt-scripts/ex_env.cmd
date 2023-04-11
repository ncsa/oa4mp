# Here is an example of a script that reads in a couple of environment files in both
# standard properties format and JSON then echos out to the console what was read.

set_env -in test_env.props;

# Now print out the contents

print_env;

# show you can access the values

echo ${test};

# read in some more, adding them to the current environment

set_env -json -add -in more_props.json;

echo ${test} __AND__ ${test2};

# Note that the replacement happens *before* the line is fed to the interpreter

echo done with example!;