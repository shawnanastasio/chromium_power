Chromium on POWER
=============
This repository contains a set of patches that allow the Chromium browser
to build and run on ppc64le hosts. 

In addition, this repository contains an interactive utility for
automatically applying and rebasing patches to a given chromium source tree.


Layout
----
Individual patches are roughly grouped by the part of chromium they modify.
For example, patches for the sandbox system can be found in the `sandbox` folder.

`patches.json` contains a manifest of all of the patches. In this file,
patches are grouped by the directory that they must be applied in, relative
to the chromium source directory. 

For example, patches under `"."` are to be applied in the root chromium source
directory, and patches under `"v8"` are to be applied in `<chromium source root>/v8`.


Chromium Patching Framework
----------------
`cpf.py` contains the Chromium Patching Framework, an interactive utility for
applying and rebasing patches to a given source tree.

To apply all patches listed in the manifest to a local copy of the chromium source tree,
do the following:
```
./cpf.py /path/to/chromium/tree
```

Example output:
```
[+] Applying "sandbox/0001-linux-seccomp-bpf-ppc64-glibc-workaround-in-SIGSYS-h.patch"... Success
[+] Applying "sandbox/0001-sandbox-Enable-seccomp_bpf-for-ppc64.patch"... Success
[+] Applying "sandbox/0001-sandbox-linux-bpf_dsl-Update-syscall-ranges-for-ppc6.patch"... Success
[+] Applying "sandbox/0001-sandbox-linux-Implement-partial-support-for-ppc64-sy.patch"... Success
```

If an error is encountered, you will be prompted with the following options:
```
[?] The following patch failed to apply:
 * /example/example.patch
What would you like to do?
 (F)ix the conflict manually
 (S)kip the patch
 (A)bort
Choice? [A]:
```

You may fix the conflict manually by following the on-screen prompts, skip the
patch, or abort the application.

If you encounter a patch that fails to apply against the latest chromium git HEAD,
please submit an issue. Alternatively, if you are able to fix it yourself, please
do so and submit a Pull Request.


Copyright
------
All files ending in `.patch` (patch files) are owned by the patch author, 
listed at the top of the file. These patch files are considered derivative
works of the software components they modify and are therefore licensed under
the same license as the original work.

All other files are copyright Shawn Anastasio and licensed under the GNU GPL v3.0
license. See `LICENSE.md` for the full license text.
