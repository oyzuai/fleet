# Executor image base

The executor image uses the Docker Official Image `buildpack-deps:noble-scm`,
based on Ubuntu 24.04, as a complete pinned runtime material:

- OCI index: `sha256:9eb8dccd73fd735719771e8589b1a7aceb138d792866af0784ede1a3ea2d6107`.
- Linux amd64 manifest: `sha256:7cd30264921d935e52e399fdbae125f6a5a763e89a5a031362c8f449fccddbbc`.
- Official image metadata: <https://github.com/docker-library/repo-info/blob/master/repos/buildpack-deps/remote/noble-scm.md>.
- Upstream source revision: `60dc5f9555c521de086b2f5770514faf69ee2cc4` in <https://github.com/docker-library/buildpack-deps>.
- SCM recipe: <https://github.com/docker-library/buildpack-deps/blob/60dc5f9555c521de086b2f5770514faf69ee2cc4/ubuntu/noble/scm/Dockerfile>.
- Parent recipe: <https://github.com/docker-library/buildpack-deps/blob/60dc5f9555c521de086b2f5770514faf69ee2cc4/ubuntu/noble/curl/Dockerfile>.

The SCM recipe installs Git, Mercurial, OpenSSH client, Subversion and procps
with Ubuntu's package manager. Its parent includes ca-certificates, curl,
GnuPG, netbase, sq, wget and tzdata. The complete base retains package-managed
Git helpers and dependency libraries, including the HTTPS transport; Fleet
does not transplant a host Git executable or rebuild these packages.

Packaged software keeps its original licenses. Package copyright and source
information under `/usr/share/doc`, including `/usr/share/doc/git/copyright`,
and license texts under `/usr/share/common-licenses`, including Git's GPL-2,
remain in the image. The Docker recipe's license does not replace those
component licenses. Ubuntu's Git source-package information is available at
<https://launchpad.net/ubuntu/+source/git>.

The upstream Docker recipe license follows, from that revision's `LICENSE`:

Copyright (c) 2014 Docker, Inc.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
