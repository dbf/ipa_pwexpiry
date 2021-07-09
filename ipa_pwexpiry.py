#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# License: EUPL-1.2
"""List users by krbPasswordExpiration and optionally send IPA password
expiration warning by mail. Modify this code (mostly variables) according to
your requirements. You most likely want to modify the mail message text as
well. Keep an eye on file permissions, since the code contains the bind user's
password in cleartext. Make sure that all users' LDAP records contain a valid
mail address.
"""

import os
import sys
import datetime
import smtplib
import argparse
import operator
import ldap

# variables
# set this to 1 as soon as you have modified at least the variables to suit
# your requirements
I_HAVE_MODIFIED_THE_CODE_TO_SUIT_MY_REQUIREMENTS = 0
# expiration warning time window (days)
TIME_WINDOW = 7
# working with LDAP bind user here, defining an IPA service
# and working with Kerberos key is considered more elegant
LDAP_SRV_URI = "ldaps://"
LDAP_SRV_FQDN = "ipasrv.example.com"
LDAP_SRV = LDAP_SRV_URI + LDAP_SRV_FQDN
LDAP_TRACELEVEL = 0
CA_CRT_FILE = "/etc/ipa/ca.crt"
BIND_DN = "uid=ldapbind,CN=users,CN=accounts,DC=example,DC=com"
BIND_PW = "bind_user_password_goes_here"
BASE_DN = "CN=users,CN=accounts,DC=example,DC=com"
# search for users of group "remind" only, your mileage may vary
SEARCH_FILTER = "(&(objectClass=inetOrgPerson)(memberOf=CN=remind,CN=groups,CN=accounts,\
                DC=example,DC=com)(!(nsaccountlock=TRUE)))"
SEARCH_ATTRIBUTES = ["cn", "uid", "mail", "krbPasswordExpiration"]
SEARCH_SCOPE = ldap.SCOPE_SUBTREE
# mail server to send out pw expiration warnings
MY_MAILEX = "mail.example.com"
FROM_ADDR = "admin@example.com"
CC_ADDR = "deputy-admin@example.com"
MAIL_SUBJ = "FOO IPA password expiration warning"
# now and now plus 1 week as int in proper notation
# timestamps in IPA are all UTC
NOW = datetime.datetime.utcnow()
NOW_ASN1 = int(NOW.strftime("%Y%m%d%H%M%S"))
NOW_PLUS_TW = datetime.datetime.utcnow() + datetime.timedelta(days=TIME_WINDOW)
NOW_PLUS_TW_ASN1 = int(NOW_PLUS_TW.strftime("%Y%m%d%H%M%S"))
EXPIRED_LIST = []
CMDLINE_ARGS = None

# functions
# get user data from IPA/LDAP


def get_users_from_ldap():
    """Return a sorted list of dicts containing user information from LDAP.
    Each dict (hopefully) contains four elements:
    uid, cn, mail, krbPasswordExpiration
    and their corresponding values.
    """
    global LDAP_TRACELEVEL
    if CMDLINE_ARGS.debug:
        # increase trace_level to 2 or 3, if you want to see more debug output
        LDAP_TRACELEVEL = 1
    try:
        lquery = ldap.initialize(LDAP_SRV, trace_level=LDAP_TRACELEVEL)
        # Either disable cert validation...
        #lquery.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        # ...or force cert validation (recommended).
        lquery.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
        lquery.set_option(ldap.OPT_X_TLS_CACERTFILE, CA_CRT_FILE)
        # Force libldap to create a new SSL context (must be last TLS option!)
        lquery.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        # set protocol version
        lquery.protocol_version = ldap.VERSION3
        # bind
        lquery.simple_bind_s(BIND_DN, BIND_PW)
    except ldap.LDAPError as lerr:
        srv_splitname = LDAP_SRV_FQDN.split(".")
        lerr_dict = lerr.args[0]
        lerr_desc = lerr_dict.get("desc", lerr_dict.get("info", str(lerr)))
        print("LDAP error: " + lerr_desc + " on server " + srv_splitname[0])
        sys.exit(1)
    else:
        try:
            raw_res = lquery.search_s(BASE_DN, SEARCH_SCOPE, SEARCH_FILTER, SEARCH_ATTRIBUTES)
        except ldap.LDAPError as lerr:
            srv_splitname = LDAP_SRV_FQDN.split(".")
            lerr_dict = lerr.args[0]
            lerr_desc = lerr_dict.get("desc", lerr_dict.get("info", str(lerr)))
            print("LDAP server on " + srv_splitname[0] + " says: " + lerr_desc)
            sys.exit(1)
        finally:
            # close LDAP connection
            lquery.unbind_s()
    # raw LDAP output is a list of tuples, we want the 2nd element of
    # each tuple, which is a dict and have it sorted by krbPasswordExpiration
    sorted_res = sorted([i[1] for i in raw_res], key=operator.itemgetter(
        'krbPasswordExpiration'), reverse=True)
    # while it is a relatively safe assumption that dicts from IPA LDAP contain
    # uid, cn and krbPasswordExpiration entries, the mail entry may be missing,
    # so check and add an empty one if it is not there
    # also make sure that only the first mail address is chosen in case there
    # is more than one
    for _, j in enumerate(sorted_res):
        if 'mail' in j:
            tmplist = []
            tmplist.append(j['mail'][0])
            j['mail'] = tmplist
        else:
            j['mail'] = [b'']
    # bytes to string conversion
    for _, j in enumerate(sorted_res):
        for k in j.keys():
            j[k][0] = j[k][0].decode("utf-8", errors="strict")
    return sorted_res

# print user list


def list_users(sorted_res):
    """Takes a list of dicts and prints them as a table.
    Each dict must contain four elements
    uid, cn, mail, krbPasswordExpiration and their corresponding values.
    """
    print("{:<11} {:<26} {:<35} {:<15}".format(
        'UID', 'Name', 'Mail', 'krbPasswordExpiration'))
    print("{:<11} {:<26} {:<35} {:<15}".format(
        '===', '====', '======', '====================='))
    for _, single_res in enumerate(sorted_res):
        print("{:<11} {:<26} {:<35} {:<15}".format(
            ''.join(str(single_res['uid'][0])),
            ''.join(str(single_res['cn'][0])),
            ''.join(str(single_res['mail'][0])),
            ''.join(str(single_res['krbPasswordExpiration'][0]))))

# mail stuff


def create_message(single_fn, single_acc, single_expdate):
    """Create mail warning message and return as str.
    """
    MAIL_HEADER = """
-----------------------------------------------------------------------
FOO IPA password expiration warning - please read completely, then act.
-----------------------------------------------------------------------
This warning was sent automatically by a software.
Password expiration warnings will be sent only once.
"""

    mail_body = '\nHi ' + single_fn + ',' + '\n\n' + \
        'the password for your FOO account \"' + single_acc + \
        '\" will expire in less than ' + \
        str(TIME_WINDOW) + ' days\n(actually on ' + \
        single_expdate + ').' + \
        '\nPlease change your password as soon as possible.\n'

    MAIL_FOOTER = """
In order to change your password, please proceed as follows:
[message to your users goes here]
"""
    msg_to_be_sent = MAIL_HEADER + mail_body + MAIL_FOOTER
    return msg_to_be_sent


# main
def main():
    """main program
    parse cmdline, call functions
    """
    global CMDLINE_ARGS
    cmdline_parser = argparse.ArgumentParser(
        description='Get list of IPA users with krbPasswordExpiration, optionally notify users.')
    cmdline_parser.add_argument('-d', '--debug',
                                help='debug output', action='store_true')
    cmdline_parser.add_argument('-n', '--dry-run',
                                help='dry run, print mail but do not send', action='store_true')
    cmdline_parser.add_argument('-s', '--send',
                                help='send password expiration warning mail',
                                action="store_true")
    CMDLINE_ARGS = cmdline_parser.parse_args()
    if I_HAVE_MODIFIED_THE_CODE_TO_SUIT_MY_REQUIREMENTS != 1:
        print(os.path.basename(sys.argv[0])
              + ': This program will NOT work for you unless you modify the source code.')
        sys.exit(1)
    user_list = get_users_from_ldap()
    if not CMDLINE_ARGS.send and not CMDLINE_ARGS.dry_run:
        # no --send or --dry-run given, print user list and exit
        list_users(user_list)
        sys.exit(0)
    else:
        # this loop does the actual "magic"
        for _, single_res in enumerate(user_list):
            expdate = int(str(single_res['krbPasswordExpiration'][0])[0:-1])
            if expdate >= NOW_ASN1 and expdate < NOW_PLUS_TW_ASN1:
                EXPIRED_LIST.append(single_res.copy())
        # now we have all accounts with passwords about to expire (if any),
        if EXPIRED_LIST:
            for _, expired_user in enumerate(EXPIRED_LIST):
                single_fn = ''.join(expired_user['cn'])
                single_acc = ''.join(expired_user['uid'])
                single_to_addr = ''.join(expired_user['mail'])
                # we cannot send warnings without a mail address
                if not single_to_addr:
                    print("Warning: No mail address available for CN %s." %
                          single_fn)
                    continue
                single_expdate_tmp1 = ''.join(expired_user['krbPasswordExpiration'])
                single_expdate_tmp2 = datetime.datetime.strptime(
                    single_expdate_tmp1[0:-1], "%Y%m%d%H%M%S")
                single_expdate = single_expdate_tmp2.strftime('%d %b %Y, %H:%M:%S')
                single_mailheader = ("From: %s\r\nTo: %s\r\nCc: %s\r\nSubject: %s\r\n\r\n" % (
                    FROM_ADDR, single_to_addr, CC_ADDR, MAIL_SUBJ))
                single_msg = create_message(
                    single_fn, single_acc, single_expdate)
                single_complete_mail = single_mailheader + single_msg
                if CMDLINE_ARGS.dry_run and not CMDLINE_ARGS.send:
                    print(single_complete_mail)
                    continue
                elif CMDLINE_ARGS.send:
                    try:
                        my_mailex_inst = None
                        my_mailex_inst = smtplib.SMTP(MY_MAILEX)
                        if CMDLINE_ARGS.debug:
                            my_mailex_inst.set_debuglevel(1)
                    except smtplib.socket.error:
                        print("Error: Cannot connect to SMTP server " + MY_MAILEX)
                        sys.exit(1)
                    try:
                        my_mailex_inst.sendmail(
                            FROM_ADDR, single_to_addr, single_complete_mail)
                        if CMDLINE_ARGS.debug:
                            print("Debug: Sent expiration notice to %s" % single_to_addr)
                    except smtplib.SMTPException:
                        print("Error: Unable to send expiration notice to %s" % single_to_addr)
                        sys.exit(1)
                    finally:
                        if my_mailex_inst != None:
                            my_mailex_inst.quit()
                else:
                    sys.exit("This should not happen.")


if __name__ == "__main__":
    main()
