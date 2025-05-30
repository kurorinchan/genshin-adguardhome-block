This is a very niche script.

# tl;dr
If you are running Genshin on mac using CrossOver **and** using Adguard Home. This script
blocks `dispatchosglobal.yuanshen.com` DNS resolution exactly once.

# What
Genshin impact could run on macOS using CrossOver. However, if it successfully access
`dispatchosglobal.yuanshen.com` on launch, the process exits immediately. This script accesses
your Adguard Home server via REST API to deny DNS resotluion to the domain,
exactly once. Then reenables the name resolution so you can login the game.

Since there is a lag between *setting* a filter and the filter *taking effect*,
this script waits until the settings takes effect.

This script is not the most convenient script ever, and people have come up with
other solutions to fix this problem (e.g. editting /etc/hosts in a script).

# Note
Pipenv is not required. It should run with `python3` and `curl`.