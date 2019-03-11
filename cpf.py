#!/usr/bin/env python3

# Copyright 2019 Shawn Anastasio
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


import os
import re
import sys
import json
import time
import shutil
import hashlib
import argparse
import subprocess
from enum import Enum

PATCH_LIST = "patches.json"
CHROMIUM_DIR = None
DRY = False
FILE_CACHE = {}
OUT_DIR = "out/"

class TColor:
    RESET = "\u001b[0m"
    YELLOW = "\u001b[33m"
    GREEN = "\u001b[32m"
    RED = "\u001b[31m"

def log(msg, newline = True):
    print("{}[+]{} {}".format(TColor.GREEN, TColor.RESET, msg), \
            end=("\n" if newline else ""))

def log_e(msg, newline = True):
    print("{}[-]{} {}".format(TColor.RED, TColor.RESET, msg), \
            end=("\n" if newline else ""))

def md5(string):
    return hashlib.md5(string.encode("UTF-8")).hexdigest()

def md5_file(path):
    with open(path, "r") as f:
        return md5(f.read())

def prompt(question, choices, default, insensitive=True):
    while True:
        print(question)
        
        choice = input("Choice? [{}]: ".format(default))
        if choice == "":
            return default;

        if insensitive:
            choice = choice.upper()

        if choice in choices:
            return choice

        print()
        log_e("Invalid choice!\n")

class PatchFailReason(Enum):
    CONFLICT = 0 # Conflict while applying patch
    NOFILE = 1 # No such file or directory
    ALREADY = 2 # Patch already applied

def patchFailReasonStr(r):
    return {
        PatchFailReason.CONFLICT: "Conflict",
        PatchFailReason.NOFILE: "No such file or directory",
        PatchFailReason.ALREADY: "Patch already applied",
    }[r];

class PatchFailedError(Exception):
    def __init__(self, reason, output):
        super().__init__()
        self.reason = reason
        self.output = output

def apply_patch(directory, patch_path, dry=False):
    # Cache affected files
    with open(patch_path, "r") as f:
        patch_data = f.read()

    files = re.findall("^--- a/(.*)", patch_data, re.MULTILINE)
    files = [directory + "/" + x for x in files]
    
    for fil in files:
        try:
            with open(fil, "r") as f:
                FILE_CACHE[fil] = f.read()
        except FileNotFoundError:
            # Patch references file that doesn't exist, throw exception
            raise PatchFailedError(PatchFailReason.NOFILE, b"")

    try:
        dry_args = "--dry-run" if dry else ""

        out = subprocess.check_output(["bash", "-c",
            "cd {}; LOCALE=C patch {} -p1 < {}".format(directory, dry_args, patch_path)], \
            stderr=subprocess.STDOUT)

        #print("Patch succeeded:", out.decode("UTF-8"))
    except subprocess.CalledProcessError as e:
        #print("Patch failed:", e.output.decode("UTF-8"))
        if b"can't find file to patch at input line" in e.output:
            raise PatchFailedError(PatchFailReason.NOFILE, e.output)
        elif b"Reversed (or previously applied) patch detected!" in e.output:
            raise PatchFailedError(PatchFailReason.ALREADY, e.output)
        else:
            raise PatchFailedError(PatchFailReason.CONFLICT, e.output)

def generate_hunk(path, old_str, new_path):
    try:
        l1 = "a/" + path
        l2 = "b/" + path
        diff_p = subprocess.Popen(["diff", "-u", "--label={}".format(l1), \
                    "--label={}".format(l2), "-", new_path], \
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, \
                    stdin=subprocess.PIPE)

        stdout, stderr = diff_p.communicate(old_str.encode("UTF-8"))
        return stdout.decode("UTF-8").rstrip('\n')
    except Exception as e:
        log_e("An unknown error occurred while generating diff: " + str(e))
        sys.exit(1)

UPDATED_PATCHES = {}
def update_patch(patch, file_path, hunk):
    orig_patch = patch
    if patch in UPDATED_PATCHES:
        patch = UPDATED_PATCHES[patch]

    with open(patch, "r") as f:
        patch_lines = f.readlines()

    # Find start and end of the target file's hunk (inc.)
    start = -1
    end = -1
    for i in range(len(patch_lines)):
        if start == -1:
            if re.match("--- a/" + file_path, patch_lines[i]):
                start = i
        else:
            if re.match("-- ", patch_lines[i]) or \
                    re.match("diff ", patch_lines[i]):
                end = i
                break

    if start == -1 or end == -1:
        log_e("Failed to find start/end of patch ([{}, {}])! Aborting."\
                .format(start, end))
        sys.exit(1)

    # Remove old hunk
    n_remove = end - start
    for _ in range(n_remove):
        patch_lines.pop(start)

    # Insert new hunk
    hunk_lines = hunk.split("\n")
    for i in range(len(hunk_lines)):
        patch_lines.insert(start + i, hunk_lines[i] + "\n")

    # Write new patch to OUT_DIR
    parent_dir = re.findall(".*/(.*)/.*", patch)[0]
    os.makedirs(OUT_DIR + "/" + parent_dir, exist_ok=True)
    new_patch_path = OUT_DIR + "/" + parent_dir + "/" + \
                        os.path.basename(patch)
    with open(new_patch_path, "w") as f:
        f.writelines(patch_lines)

    UPDATED_PATCHES[orig_patch] = new_patch_path
    log("Updated patch written to {}".format(new_patch_path))

def main():
    global PATCH_LIST, CHROMIUM_DIR, DRY, OUT_DIR
    
    # Parse arguments
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-d", "--dry-run", action="store_true", dest="dry",
                            help="Don't actually apply the patches. May result in some failures.")
    argparser.add_argument("-o", "--out", type=str,
                            help="Output directory for fixed patches. (Default: ./out)")
    argparser.add_argument("-p", "--patch-list", type=str, dest="list",
                            help="Location of patch manifest file (Default: ./patches.json)")
    argparser.add_argument("chromium_dir", type=str,
                            help="Path of chromium source tree to patch.")
    args = argparser.parse_args()

    if args.dry:
        DRY = True
    if args.out:
        OUT_DIR = args.out
    if args.list:
        PATCH_LIST = args.list
    CHROMIUM_DIR = args.chromium_dir

    if DRY:
        log_e("WARNING: Patches that depend on other patches in the " + \
            "series will fail in dry-run mode!")
        print()
        time.sleep(5)

    run_patcher()

def run_patcher():
    # See if there's a .cpfcache file
    cpfcache_path = CHROMIUM_DIR + "/.cpfcache"
    if os.path.exists(cpfcache_path):
        with open(cpfcache_path, "r") as f:
            cpfcache = json.load(f)
            log("{} found! Skipping patches listed in this file.".format(cpfcache_path))
    else:
        cpfcache = {}

    # Load patches
    with open(PATCH_LIST, "r") as f:
        try:
            patches = json.load(f)
        except Exception as e:
            print("Failed to load patches:", e)
            sys.exit(1)

    failures = {}
    for d in patches:
        for p in patches[d]:
            log("Applying \"{}\"... ".format(p), newline=False)
            dest_dir = CHROMIUM_DIR + "/" + d
            patch_path = os.getcwd() + "/" + p

            # Skip patches in the cpfcache
            if d in cpfcache and p in cpfcache[d]:
                print("{}Skipped (already applied){}".format(TColor.YELLOW, TColor.RESET))
                continue

            try:
                apply_patch(dest_dir, patch_path, dry=DRY)
                print("{}Success{}".format(TColor.GREEN, TColor.RESET))

                # Add this to the cpfcache
                if not (d in cpfcache):
                    cpfcache[d] = []
                
                cpfcache[d].append(p)

                # Flush cpfcache
                with open(cpfcache_path, "w+") as f:
                    f.write(json.dumps(cpfcache))

            except PatchFailedError as e:
                reason_str = patchFailReasonStr(e.reason)
                print("{}Fail ({}){}".format(TColor.RED, reason_str, TColor.RESET))
                failures[p] = e.reason
                if not DRY and e.reason != PatchFailReason.ALREADY:
                    prompt_fail_action(e.reason, dest_dir, patch_path, e.output)

                # Remove any rej files
                rejs = re.findall("[0-9]+ out of [0-9]+ hunks? [a-zA-Z]+ -- saving rejects to file (.*rej)", e.output.decode("UTF-8"))
                for r in rejs:
                    os.unlink(dest_dir + "/" + r)

    print()
    log("Done.")

    if len(failures):
        print()
        log_e("Errors were encountered when applying the following patches:")
        for k, v in failures.items():
            reason_str = patchFailReasonStr(v)
            print(" {}*{} {}: {}{}{}".format(TColor.RED, \
                    TColor.RESET, k, TColor.RED, reason_str, TColor.RESET))

def prompt_fail_action(reason, dest_dir, patch, output):
    print("\n{}[?]{} The following patch failed to apply:".format(TColor.YELLOW, TColor.RESET))
    print(" {}*{} {}".format(TColor.RED, TColor.RESET, patch))
    choice = prompt("What would you like to do?\n" +  \
                    " (F)ix the conflict manually\n" + \
                    " (S)kip the patch\n" + \
                    " (A)bort", ["F", "S", "A"], "A") 

    if choice == "F":
        fix_conflict(reason, dest_dir, patch, output)
        return
    elif choice == "S":
        return
    else:
        log("Aborting.")
        sys.exit(0)

def fix_conflict(reason, dest_dir, patch, output):
    if reason == PatchFailReason.NOFILE:
        log_e("Conflict fix assistance is unimplemented for this type of failure. Aborting.")
        sys.exit(0)

    rejs = re.findall("[0-9]+ out of [0-9]+ hunks? [a-zA-Z]+ -- saving rejects to file (.*rej)", output.decode("UTF-8"))
    files = [x[:-4] for x in rejs]
   
    print()
    log("The following files had conflicts:")
    hashes = {}
    for f in files:
        f_path = dest_dir + "/" + f
        print(" {}*{} {}".format(TColor.RED, TColor.RESET, f_path))

        # Hash the affected files so we can confirm they changed
        hashes[f] = md5_file(f_path)

    log("The failed hunks are in each file's corresponding .rej file.")
    input("Please resolve these conflicts and press ENTER. ")
    print()

    # Confirm that all affected files were modified
    while True:
        unmodified = []
        for f in files:
            new_hash = md5_file(dest_dir + "/" + f)
            if new_hash == hashes[f]:
                unmodified.append(f)

        if len(unmodified):
            log_e("The following files were unmodified:")
            for f in unmodified:
                print(" {}*{} {}".format(TColor.RED, TColor.RESET, f))

            log_e("You must manually apply the rejected hunks to these files.")
            choice = prompt("(S)kip unmodified files\n" + \
                            "(R)etry", ["S", "R"], "R")

            if choice == "S":
                log("Skipping files...")
                break
        else:
            break

    # Regenerate patches for all modified files
    modified = set(files) - set(unmodified)
    for m in modified:
        full_path = dest_dir + "/" + m
        orig = FILE_CACHE[full_path]

        hunk = generate_hunk(m, orig, full_path)

        # Update patch with new hunk
        update_patch(patch, m, hunk)

if __name__ == "__main__":
    main()
