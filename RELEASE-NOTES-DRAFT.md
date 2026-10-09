# Release-notes draft — new-app prompt fixes (version left to the maintainer)

Four gaps in the v1.0.28 new-app prompt, found in a code review on 2026-10-09
(not reported by users, not measured on a device). Each has a test that fails
without the fix; the IPv6 one runs through real netfilter (nft) in a network
namespace and was checked against a sabotaged build.

1. **One all-ports rule silenced the question for every port.** `rules.Decides`
   counted any inbound rule whose ports matched — including a country or feed
   deny, or an allow for one admin PC, over *all* ports. With such a rule ZFW never
   asked, and every new container port stayed closed by the DNAT guard without a
   word. Now an all-ports rule counts only when it speaks for the whole LAN (source
   any or a range containing the LAN, no schedule); a rule that names the port
   counts as before. (`internal/rules/reach.go`, test `decides_test.go`)

2. **Deleting the rule an answer became did not withdraw the answer.** The entry
   kept its state in `apps.json`, and once the rule was gone from the applied set
   the app chain re-admitted the port — deleting the rule and applying left it open.
   Now an answered entry whose rule is no longer in `rules.json` is dropped and the
   port judged again: still new → asked again; in the applied inventory → closed.
   (`apps.Withdraw`, tests `TestDeletedAnswerRule*`)

3. **"Everyone" did not open a container port over IPv6 when Docker filters IPv6
   itself.** With Docker's ip6tables support on, IPv6 to a published port is DNAT'd
   through FORWARD and the IPv6 `DOCKER-USER` — which had no jump to an app chain, so
   the v6 DNAT guard dropped it. New chain `ZFW-APPS6`, jumped to from the IPv6
   `DOCKER-USER` in both emitters, filled by `zfw apps`, removed by `zfw revert`, shown
   by `zfw status`. On hosts without an IPv6 `DOCKER-USER` the apps script says "not
   needed" instead of "missing" (otherwise the daemon would retry every minute).
   (live test `TestAppChainsLive`, probes `*-docker-any-wan-v6`)

4. **"Block" did not end open connections.** The app chains judge new connections;
   an established one passed ahead of them. Now every narrowing — Block, Everyone →
   LAN only, mode → blocked, a withdrawn answer — flushes conntrack for that port,
   the same targeted teardown an apply does (v1.0.21). The first sync after a daemon
   start only records the state. (tests `TestNarrowingAnAnswerFlushesConntrack`,
   `TestModeBlockFlushesPendingConnections`)

Upgrade: nothing to do beyond installing; the next apply creates `ZFW-APPS6`.
