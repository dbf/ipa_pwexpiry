# ipa_pwexpiry
This Python script may be useful for FreeIPA [1] admins.
All others may consider it an example of mediocre Python programming.
It queries IPA's LDAP database and shows a list of users with password expiry date.
It optionally sends warning mails to users with passwords about to expire.
Sending warning mails is meant to be used with `cron`.
You will need to modify the source code to make it work.
Tested with FreeIPA 4.6.x.
You will need to create a LDAP bind user in FreeIPA in advance.
License: EUPL-1.2

[1] https://www.freeipa.org/
