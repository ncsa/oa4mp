# Basic script
# A few things to note.
# First, obviously, lines that start with a hashtag (#) are ignored.
# Next, the line ends with a semi-colon (;), so the next two physical lines are treated as a single line

print_token
eyJ0eXAiOiJKV1QiLCJraWQiOiIyQkY5NTVDMjA0QjU1NTgzQjRCNzU3REI5QjY0RDE2OSIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwczovL215LmJvZ3VzLmlzc3VlciIsImF1ZCI6Im15LWF1ZGllbmNlIiwiaWF0IjoxNTY4OTA2NTgwLCJuYmYiOjE1Njg5MDY1ODAsImV4cCI6MTU2ODkxNjU4MH0.YEeAFQPdQEupKiUWmrfY9NEl6eoRpWQ4bzC8W4w4pnDjgeJOBazlMpUB5BMZMuH_vv04CaxzyXYdugF39jKvpTRE5ydwRcTezwkIea6OZJUS2VCX_F-YSajll4ddAkUC9oB0Qk4QtW5c72Bo1iUXSQ4EGWithnuQXp0qp4y25Kegrel2iRxgpa-IUQENA7o9fZrqJnY45MkfJ-9nvygJaD2b2QSAkh4cocGLL4_xF3hjON_IEsBRcdjq079TjVA-3-pUUzVmu_irFsrmgYDNQE_vQDNLByENDdoj3p9GeBtx1odebYWUW86s0s63JtOOXgQ17fpvi0c4cGz2asQyGg;

# You may have as many commands in one file as you like. Note the ending semi-colons except the last command that
# breaks over several lines. 
echo here are is some output;
set_output_on false;
echo This is ignored;
set_output_on true;
echo
 This
       is
          printed
                   too..;
