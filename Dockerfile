# Default to the Docker Hub container registry
ARG DOCKER_REGISTRY=index.docker.io

# Default to the official Python Debian image.
#
# The floating 3.8 tag rather than the pinned 3.8.0: it is the same interpreter
# line on a newer Debian, and the buster image it replaces carried 14 MB of
# distribution that nothing here uses. Override PYTHON_IMAGE to pin a build.
ARG PYTHON_IMAGE=${DOCKER_REGISTRY}/python:3.8-slim


FROM ${PYTHON_IMAGE} AS build-image

WORKDIR /tmp/build-kubiscan
COPY requirements.txt requirements.txt

# The default image provides `pip`, `pip3`, `python` and `python3` commands and
# for portability's sake, the `pip3` and `python3` names will be used in this
# configuration.

# Install Python dependencies from requirements.txt
# As customary with Python projects, the requirements.txt, when provided,
# should contain all packages necessary to run the Python source for the
# project. As such changes to the dependencies would merely warrant a change to
# the requirements.txt file, while the Dockerfile files remain unaffected.
# Installed into a directory of their own so that the runtime stage can take the
# dependencies and nothing else. Copying the whole of /usr/local also carried
# pip, setuptools and wheel - build tooling with no business in a scanner - plus
# a second copy of anything the base image already had at that path.
#
# --no-compile keeps the bytecode caches out. They are a build artefact of the
# machine that compiled them, Python rebuilds what it needs at import time, and
# across 140 package directories they are not a rounding error.
RUN pip3 install --no-compile --no-cache-dir --target=/deps -r requirements.txt


FROM ${PYTHON_IMAGE} AS run-image

# Only the dependencies, dropped where the interpreter already looks for them.
COPY --from=build-image /deps /usr/local/lib/python3.8/site-packages

# Fail the build here rather than at the first scan if the trimming went too far.
RUN PYTHONDONTWRITEBYTECODE=1 python3 -c 'import kubernetes, prettytable, yaml, requests'

# Copy source
COPY . /opt/kubiscan

# Create kubiscan executable shortcut for all users
# NOTE that this image does not default to using this shortcut but rather
# resorts to directly starting the KubiScan Python script. It may prove useful
# to remove this shortcut altogether unless end-users are expected to spawn a
# Bash inside the resulting container in which case the `kubiscan` shortcut
# will come in handy.
RUN set -ex \
  && echo 'python3 /opt/kubiscan/KubiScan.py $@' > /usr/local/bin/kubiscan \
  && chmod a+x /usr/local/bin/kubiscan \
  && which kubiscan

# Create a non-root user and group
RUN set -ex \
  && addgroup kubiscan \
  && adduser \
    --no-create-home \
    --disabled-password \
    --gecos ',,,,' \
    --ingroup kubiscan \
    --disabled-login \
    kubiscan \
  && > /var/log/faillog \
  && > /var/log/lastlog

# Environment variable to know if running in a container
ENV RUNNING_IN_A_CONTAINER=true

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]