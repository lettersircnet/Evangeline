Evangeline
==========

Evangeline 1.1.5 (reborn) is a modern fork created to keep the original C++
botnet model alive while modernizing it for current IRCNet operations.

The original codebase was built by Grzegorz Rusin and contributors as a fast
C++ IRC bot with partyline control, encrypted botnet links, channel protection,
userlist replication, and modular extensions. Evangeline keeps that base and
credits the original work directly.

The Evangeline name is used in the same spirit as the older Evangeline work for
Eggdrop: not a rewrite that forgets its roots, but a practical fork that takes a
proven IRC bot and reshapes it for how networks are operated today.

Project direction
-----------------

- Preserve the original botnet, channel protection, and partyline concepts.
- Make IPv6 a first-class deployment mode.
- Make botnet and partyline links SSL by default.
- Improve IRCNet-focused op, kick, and defense timing without ignoring server
  flood policy.
- Keep full userlist replication across linked bots so slaves and leafs can act
  locally without waiting on the hub for every decision.
- Add modern operator login options such as OTP and fast-login while keeping
  owner-controlled enablement.
- Keep the original authors visible while documenting the Evangeline fork work.

Credits
-------

Original C++ bot:
Grzegorz Rusin <grusin@gmail.com> and contributors.

Evangeline fork:
Marco d'Angelo <marco@dangelo.mobi>.
