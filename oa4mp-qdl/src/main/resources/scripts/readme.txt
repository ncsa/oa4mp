OLD!!! Format of the scripts has changed. None of this probably works.

This directory contains several scripts whose sole purpose is to test the
ability of the QDlJSONConfigUtil to load them and keep them straight.
Reading in a directory of scripts reads in each script and **every** file
so that at run time, they may be treated as a VFS (virtual file system) and
modules, etc. can be loaded