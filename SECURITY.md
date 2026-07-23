If you think you have found a security problem with Nethogs,
please report it privately to arnout@bzzt.net .

Nethogs is meant to be used by trusted users: it requires
root (or various capabilities) to function. We don't
encourage making nethogs suid root and recommend explicitly
giving the users that should be able to run nethogs the
necessary permissions instead. We don't consider privilege
escalation via a suid nethogs a vulnerability, though we
might still fix them as security hardening improvements when
reported.

Running nethogs on a machine processing untrusted network
traffic or allowing untrusted users is supported to a point:
it is expected that attackers with such authorizations can
cause resource usage / denial of service conditions in nethogs,
but it should not allow attackers to gain privilege escalation
though this path.

As for correctness, nethogs is meant as a "quick overview" utility,
not as a reliable accounting tool. It is possible that an untrusted
user could shape their traffic/network usage patterns to
circumvent reliable recording by nethogs.
