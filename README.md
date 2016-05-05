
Redis PAM Authentication module POC
===

This module replaces the original Redis AUTH command with an alternative
implementation that uses the Linux PAM facility to authenticate users.

**This module should be used as a proof of concept only.  It provides an
extreme example of how modules can extend Redis beyond the standard
Redis Module API.**

Quick start guide
--

1. Build a Redis server with support for modules.
2. Create a `REDIS_SRC_DIR` environment variable that points to your Redis source code: `export REDIS_SRC_DIR=<dir>`.
2. Build the password module: `make`
3. To load the module, Start Redis with the `--loadmodule /path/to/module.so` option, add it as a directive to the configuration file or send a `MODULE LOAD` command.

What it does
--

This module does not create new commands, it only modifies the way `AUTH` works.

Once loaded, `AUTH` expects users to provide both username and password in the
format `<user>:<password>`.  This is validated against PAM as a `redis` service
authentication request.

The `requirepass` settings is ignored as long as the module remains loaded
in Redis.

Why use PAM
--

There are several benefits for using PAM:

* Rely on OS user authentication, using same credentials use for OS access.

* Advanced OS authentication configuration such as Active Directory/LDAP
  membership.

* Additional security features are "for free", like failed login throttling,
  granular restrictions based on source IP address, etc.

Disclaimer
--

This module is an example of a "rogue" module, which is not confined to the
Redis Module API but instead messes with Redis internals:

* Compiles against Redis header files so it can directly manipulate otherwise
  inaccessible structures (e.g. `struct client`).

* Accesses Redis symbols exported by `redis-server`.

* Employs binary patching techniques to overwrite code in memory, thereby 
  creating hook points not otherwise possible.

As a result, this module is limited!

* It may not work (and even crash) a Redis server other than the one it was compiled for.

* It currently only supports Linux and the x86_64 architecture.

Contributing
---

Issue reports, pull and feature requests are welcome.

License
---

AGPLv3 - see [LICENSE](LICENSE)
