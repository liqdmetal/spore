# SPDX-License-Identifier: Apache-2.0
#
# ClusterFuzzLite build environment for spore — the maintainer-suggested
# successor to the declined OSS-Fuzz upstream submission (google/oss-fuzz
# PR 16145: "not mature enough ... take a look at ClusterFuzzLite").
#
# Same recipe as the oss-fuzz fork's projects/spore/Dockerfile, with the one
# difference CFL mandates: the source is COPYed in during docker build rather
# than git-cloned (https://google.github.io/clusterfuzzlite/build-integration/).
FROM gcr.io/oss-fuzz-base/base-builder-go

# Pin Go to the spore module's toolchain (go.mod: go 1.23.x) so the
# go-118-fuzz-build rewrites compile against the same stdlib as local runs.
RUN wget https://go.dev/dl/go1.23.12.linux-amd64.tar.gz \
&& mkdir temp-go \
&& rm -rf /root/.go/* \
&& tar -C temp-go/ -xzf go1.23.12.linux-amd64.tar.gz \
&& mv temp-go/go/* /root/.go/ \
&& rm -rf temp-go go1.23.12.linux-amd64.tar.gz

# go-118-fuzz-build (v1 flow) rewrites the harness file's `testing` import to
# this shim package. Pinned to the commit the targets were verified against —
# the same pin as the oss-fuzz fork's projects/spore/Dockerfile.
RUN git clone https://github.com/AdamKorcz/go-118-fuzz-build $SRC/fuzzbuild \
&& git -C $SRC/fuzzbuild checkout a70c2aa677fa43583571959478decabe02a96cd6

COPY . $SRC/spore
WORKDIR $SRC/spore
COPY ./.clusterfuzzlite/build.sh $SRC/
