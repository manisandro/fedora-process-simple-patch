#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# process-simple-patch.py
#
# This script automates most of the tasks for processing Simple Patch Requests
#   See the Simple Patch Policy at
#       https://fedoraproject.org/wiki/Policy_for_simple_patches#Simple_Patch_Policy
#
# Copyright (C) 2014 Sandro Mani, Igor Gnatenko
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


from bugzilla.rhbugzilla import RHBugzilla3
from fedora.client import AccountSystem
import fedora_cert
import sys
import re
import getpass
import subprocess
import tempfile
import os
import shutil
import urllib
import glob
import hashlib
import argparse


def patsearch(pat, text, errormsg):
    match = pat.findall(text)
    if not match:
        raise Exception(errormsg)
    return match


def md5sum(filename):
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(128 * md5.block_size), b''):
            md5.update(chunk)
    return md5.hexdigest()


class ShellCmd:
    def __init__(self, cmd, stdin=None):
        self.p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=stdin)

    def stdout(self):
        return self.p.stdout

    def stderr(self):
        return self.p.stderr

    def communicate(self, errormsg, exitcodetest=lambda code: code == 0):
        (stdout, stderr) = self.p.communicate()
        if not exitcodetest(self.p.returncode):
            raise Exception("%s:\n%s" % (errormsg, str(stderr)))


class Bugzilla:
    def __init__(self, args):
        self.bzclient = RHBugzilla3(url="https://bugzilla.redhat.com/xmlrpc.cgi")
        self.bugid = args.bugid
        # Do bugzilla login (so that the email of the reporter/request author is visible)
        if args.user:
            self.username = args.user
        else:
            self.username = raw_input(' * RHBZ username: ')
        self.password = getpass.getpass(' * RHBZ password: ')
        self.login()

    def login(self):
        try:
            self.bzclient.login(self.username, self.password)
        except:
            raise Exception("Bugzilla login failed")

    def logout(self):
        self.bzclient.logout()

    def fetch_bug(self):
        try:
            bug = self.bzclient.getbug(self.bugid)
        except:
            self.logout()
            raise Exception("Failed to fetch bug {}".format(self.bugid))
        return bug

    def comment(self, comment):
        bug = self.fetch_bug()
        bug.addcomment(comment)

    def set_status(self, status):
        bug = self.fetch_bug()
        bug.setstatus(status)


class ValidateError(Exception):
    def __init__(self, msg, bugzilla):
        bugzilla.comment(msg)


def getSimplePatchRequest(bugzilla):
    bug = bugzilla.fetch_bug()

    # Search comments for a Simple Patch Request
    patReq = re.compile(r"^\s*Simple Patch Request\s*$", re.M)
    patPatch = re.compile(r"^\s*Patch\[(\w+)\]\s*=\s*(.+)\s*$", re.M)
    patBuild = re.compile(r"^\s*ScratchBuild\[(\w+)\]\s*=\s*(.+)\s*$", re.M)
    patFasID = re.compile(r"^\s*Submitter\s*=\s*(\S+)\s*$", re.M)

    for comment in reversed(bug.comments):
        text = comment["text"]
        if re.search(patReq, text):

            # Populate request dictionary
            request = {"branches": set(), "patches": dict(), "builds": dict(), "fasid": None, "email": None, "component": None}

            for (branch, url) in patsearch(patPatch, text, "Request is missing a Patch field"):
                request["branches"].add(branch)
                if branch in request["patches"]:
                    raise Exception("Multiple Patch fields for branch %s" % branch)
                request["patches"][branch] = url

            for (branch, url) in patsearch(patBuild, text, "Request is missing a ScratchBuild field"):
                request["branches"].add(branch)
                if branch in request["builds"]:
                    raise Exception("Multiple ScratchBuild fields for branch %s" % branch)
                request["builds"][branch] = url

            request["fasid"] = patsearch(patFasID, text, "Request is missing a Submitter field")[0]
            request["email"] = comment["author"]
            request["component"] = bug.component

            # Do some validation
            for branch in request["branches"]:
                if branch not in request["patches"]:
                    raise Exception("Missing Patch for branch %s" % branch)
                if branch not in request["builds"]:
                    raise Exception("Missing ScratchBuild for branch %s" % branch)

            print " => Found Simple Patch Request for %s[%s] submitted by %s (%s)" % (bug.component, ", ".join(list(request["branches"])), request["fasid"], request["email"])
            return request

    raise Exception("Bug does not appear to contain any Simple Patch Request")


def validateFedoraUser(request):
    # Setup FAS client
    fasclient = AccountSystem()
    try:
        fasusername = fedora_cert.read_user_cert()
        print " * FAS username: %s" % fasusername
    except:
        fasusername = raw_input(' * FAS username: ')
    password = getpass.getpass(' * FAS password: ')
    fasclient.username = fasusername
    fasclient.password = password

    # Query user
    fasid = request["fasid"]
    email = request["email"]
    person = fasclient.person_by_username(fasid)

    # Validate user
    if not person:
        raise Exception("Request submitter %s does not match a known FAS username" % fasid)

    if not person["bugzilla_email"] == email:
        raise Exception("Email %s of request submitter does not match email of specified FAS user %s" % (email, fasid))

    if "cla_fpca" not in person["group_roles"] or person["group_roles"]["cla_fpca"]["role_status"] != "approved":
        raise Exception("Request submitter %s has not signed the Fedora Project Contributor Agreement" % fasid)

    if "packager" not in person["group_roles"] or person["group_roles"]["packager"]["role_status"] != "approved":
        if request["branches"].difference(set(["master"])):
            raise Exception("Request contains patches for stable-release branches, but user %s is not a packager" % fasid)

    print " => User %s successfully validated" % fasid


def downloadAndValidateData(request, bugzilla, verify_scratch=True):
    taskPat = re.compile(r"^http://koji.fedoraproject.org/koji/taskinfo\?taskID=(\d+)$")

    # Create temporary folder
    tmpdir = tempfile.mkdtemp()
    os.chdir(tmpdir)

    print " * Working directory is %s" % tmpdir

    # Clone repo
    print " * Cloning from dist-git..."
    package = request["component"]
    ShellCmd(['fedpkg', 'clone', package]).communicate("Failed to checkout %s from dist-git" % package)
    os.chdir(package)

    # Download and apply patches
    for branch in request["branches"]:

        print " * Trying to apply patch to branch %s..." % branch

        # Checkout branch
        ShellCmd(['git', 'checkout', branch]).communicate("Package %s has no branch %s" % (package, branch))

        # Download patch
        try:
            (filename, header) = urllib.urlretrieve(request["patches"][branch])
            fh = open(filename)
        except:
            raise Exception("Failed to download patch %s for branch %s" % (request["patches"][branch], branch))

        # Apply patch
        ShellCmd(['git', 'am', '--signoff'], fh).communicate("Patch %s does not apply to branch %s:" % (filename, branch))

        if verify_scratch:
            # Get the taskID from the URL
            try:
                taskId = taskPat.match(request["builds"][branch]).group(1)
            except:
                raise Exception("Invalid scratch build URL %s" % request["builds"][branch])

            # Download files from koji
            print " * Downloading scratch build %s for branch %s..." % (taskId, branch)

            os.mkdir("build-%s" % branch)
            os.chdir("build-%s" % branch)
            ShellCmd(['koji-download-scratch', taskId, '--arch', 'src']).communicate("Failed to download SRPM from koji task %s" % taskId)
            srpm = glob.glob("%s*.src.rpm" % package)
            if not srpm:
                raise Exception("Failed to locate SRPM downloaded from koji task %s" % taskId)
            srpm = srpm[0]
            rpm2cpio = ShellCmd(['rpm2cpio', srpm])
            cpio = ShellCmd(['cpio', '-idm'], stdin=rpm2cpio.stdout())
            cpio.communicate("Failed to extract SRPM %s" % srpm)
            os.chdir("..")

            # Validate scratch build
            print " * Validating scratch build %s for branch %s..." % (taskId, branch)

            # Validate source files
            try:
                with open("sources") as fh:
                    sources = [re.split(r"\s+", line)[0:2] for line in fh.readlines()]
            except:
                raise Exception("Failed to parse sources file for %s/%s" % (package, branch))

            for (hash, source) in sources:
                if hash != md5sum("build-%s/%s" % (branch, source)):
                    raise ValidateError("md5sum mismatch source %s from patched %s/%s and scratch build SRPM" % (source, package, branch),
                                        bugzilla)

            # Validate remaining files
            gitls = ShellCmd(['git', 'ls-files'])
            items = [x for x in gitls.stdout().read().split("\n") if x and x != ".gitignore" and x != "sources"]
            gitls.communicate("Failed to retreive list of files in index")
            for item in items:
                diff = ShellCmd(['diff', '-uZB', item, "build-%s/%s" % (branch, item)])
                text = diff.stdout().read()
                diff.communicate("Failed to compute diff between file %s from patched %s/%s and scratch build SRPM" % (item, package, branch), lambda code: code in [0, 1])
                if text:
                    raise ValidateError("Mismatch between file %s from patched %s/%s and scratch build SRPM:\n %s" % (item, package, branch, text),
                                        bugzilla)
        else:
            print " * WARNING: Verifying scratch builds has been disabled"

        # Simulate a push
        print " * Checking whether branch %s can be pushed..." % branch
        ShellCmd(['git', 'push', '-n']).communicate("%s/%s cannot be pushed" % (package, branch))

        print " => Branch %s is OK!\n" % branch

        return tmpdir


def pushAndBuild(request, bugzilla):
    taskPat = re.compile(r"^Task info: (http://koji.fedoraproject.org/koji/taskinfo\?taskID=\d+)$", re.M)

    for branch in request["branches"]:

        id = "%s/%s" % (request["component"], branch)

        print " * Pushing %s..." % id
        ShellCmd(['git', 'push']).communicate("Failed to push %s" % id)

        print " * Adding comment to bugzilla..."
        commit = ShellCmd(['git', 'log', '-1', '--format="commit %H%n%B"'])
        commit_sha = ShellCmd(['git', 'log', '-1', '--format="%H"'])
        out_commit = commit.stdout().read()
        out_commit_sha = commit_sha.stdout().read()
        commit.communicate("")
        commit_sha.communicate("")
        out_commit = re.sub(r"\"$", "", re.sub(r"^\"", "", out_commit))
        out_commit_sha = re.sub(r"\"$", "", re.sub(r"^\"", "", out_commit_sha))
        if branch == "master":
            scm_link = "http://pkgs.fedoraproject.org/cgit/{}.git/commit/?id={}".format(request["component"], out_commit_sha)
        else:
            scm_link = "http://pkgs.fedoraproject.org/cgit/{}.git/commit/?h={}&id={}".format(request["component"], branch, out_commit_sha)
        bugzilla.comment("Pushed to branch '{}' as {}\n{}".format(branch, scm_link, out_commit))

        print " * Launching build for %s..." % id
        fedpkg = ShellCmd(['fedpkg', 'build', '--nowait'])
        out = fedpkg.stdout().read()
        fedpkg.communicate("Failed to launch build for %s" % id)
        try:
            print " => %s " % taskPat.search(out).group(1)
        except:
            print " ! Warning: failed to retreive build url from fedpkg output"

    bugzilla.set_status("MODIFIED")
    bugzilla.logout()


class Parser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write("Error: {}\n".format(message))
        self.print_help()
        sys.exit(2)


def set_args(parser):
    parser.add_argument("bugid", action="store",
                        help="Bug number")
    parser.add_argument("--username", dest="user", action="store",
                        help="Username for RHBZ")
    parser.add_argument("--no-verify-scratch", dest="verify_scratch", action="store_false",
                        help="Do not verify scratch build (WARNING)")


def main(argv):
    descr = """
This script automates most of the tasks for processing Simple Patch Requests
See the Simple Patch Policy at https://fedoraproject.org/wiki/Policy_for_simple_patches#Simple_Patch_Policy
"""
    parser = Parser(description=descr)
    set_args(parser)
    args = parser.parse_args()
    bugzilla = Bugzilla(args)

    print "Fetching request from bug %s..." % args.bugid
    request = getSimplePatchRequest(bugzilla)

    print "Validating user %s..." % request["fasid"]
    validateFedoraUser(request)

    print "Downloading data..."
    tmpdir = downloadAndValidateData(request, bugzilla, args.verify_scratch)

    print "\n All checks passed. Make sure you've reviewed the patches."
    print ""

    build = raw_input('Push the changes and submit the package builds? [y/N]: ')
    if build.lower() != "y":
        raise Exception("Aborted by user")

    print "Building packages...\n",
    pushAndBuild(request, bugzilla)

    shutil.rmtree(tmpdir)
    print "All done!"


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception, e:
        print >> sys.stderr, "\nError: %s" % str(e)
        sys.exit(1)
