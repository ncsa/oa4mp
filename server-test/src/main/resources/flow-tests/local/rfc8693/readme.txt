This directory contains the 𝕰𝖗s𝖆𝖙𝖟 client tests for the system. The tests will run
automatically (so no intervention is needed by the tester). There is a single provisioner
client, P (localhost:p1) and two ersatz clients E1 and E2 (localhost:e1, localhost:e2).

P has a set of scopes and E1 and E2 both downscope from that. Note that part of the
test is that the downscope in the configurations works. Remember that in 8693
the clients credentials are sent to the server.

Key
---
AT, AT',... access tokens
RT, RT',... refresh tokens
IDT, IDT',.... ID tokens

List of tests
Standard
--------
These cover the basic functionality of doing the exchange. They show

----------+------------+------------------------------------------------------------------
File      | Args       |  Description
----------+------------+------------------------------------------------------------------
          |            | Minimum test with P. Sent grant type, subject token and type
          |            | and nothing else. Should get back an AT'
----------+------------+------------------------------------------------------------------
tx-basic  | T          | Minimum test, send AT, request AT, get AT'
----------+------------+------------------------------------------------------------------
tx-basic  | T          | Minimum test, send AT, request RT, get RT'
----------+------------+------------------------------------------------------------------
tx-basic  | T          | Minimum test, send AT, request IDT, get IDT'
----------+------------+------------------------------------------------------------------
tx-basic  | F          | Minimum test, send RT, request AT, get AT'
----------+------------+------------------------------------------------------------------
tx-basic  | F          | Minimum test, send RT, request RT, get RT'
----------+------------+------------------------------------------------------------------
tx-basic  | F          | Minimum test, send RT, request IDT, get IDT'
----------+------------+------------------------------------------------------------------
          |            | Minimum test, send IDT, request AT, FAIL
----------+------------+------------------------------------------------------------------
          |            | Minimum test, send IDT, request RT, FAIL
----------+------------+------------------------------------------------------------------
          |            | Minimum test, send IDT, request IDT, get IDT'
----------+------------+------------------------------------------------------------------
In tx-basic.qdl each request is done, so three tests are in each run,
controlled by the flag.

𝕰𝖗s𝖆𝖙𝖟
------
These cover everything relating  to the functioning of the exchange endpoint
for ersatz clients. Note that this first set merely tests that forking works.

----------+----------+------------------------------------------------------------------
File      | Args     | Description
----------+----------+------------------------------------------------------------------
e-fork    | -none,at |  Provision, E1 presents AT, request nothing. Verify gets AT' and RT'
----------+----------+------------------------------------------------------------------
e-fork    | -none,rt |  Provision, E1 presents RT, request nothing. Verify gets AT' and RT'
----------+----------+------------------------------------------------------------------
e-fork    | -at, at  |  Provision, E1 presents AT, request AT. Verify gets AT' and RT'
----------+----------+------------------------------------------------------------------
e-fork    | -at, rt  |  Provision, E1 presents RT, request AT. Verify gets AT' and RT'
----------+----------+------------------------------------------------------------------
e-rt      |  at      |  Provision, E1 presents AT, request RT. Verify gets RT' only
----------+----------+------------------------------------------------------------------
e-rt      |  rt      |  Provision, E1 presents RT, request RT. Verify gets RT' only
----------+----------+------------------------------------------------------------------
          |          |  Provision, E1 presents IDT, FAIL -- cannot fork with ID token
----------+----------+------------------------------------------------------------------
          |          |  Provision, E1 presents AT, requests nothing. Repeat. Show returned
          |          |  AT and RT are different, i.e., two separate flows are started.
----------+----------+------------------------------------------------------------------


Exchanges post fork

----------+------------------------------------------------------------------
File      |  Description
----------+------------------------------------------------------------------
          | Start then fork. This gets RT' and AT'. Use each
          | to get a new AT'' then RT''. Check AT has downscoped, and that aud and
          | issuer, etc. are correct. Shows that the fork works and creates a new flow.
----------+------------------------------------------------------------------
          | Provisions. E1 presents AT, E1 presents AT both get new AT' and RT'
          | Show that the resulting AT and RT are different, i.e., forks are
          | unique when done.
----------+------------------------------------------------------------------



Up/down-scope tests
----------+------------------------------------------------------------------
File      |  Description
----------+------------------------------------------------------------------
          |  Provision, E1 presents AT,  requests nothing, downscopes gets AT'
          | and RT'. Verify Downscope works. Get AT'' with original scopes. Shows
          | upscoping to E1 works. Attempt to upscope to P. This should fail,
          | since upscoping is not allowed.
----------+------------------------------------------------------------------
          |
----------+------------------------------------------------------------------
