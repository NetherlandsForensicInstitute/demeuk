FROM ubuntu:22.04

ARG DEV_CONTAINER_USER_CMD_PRE
ARG DEV_CONTAINER_USER_CMD_POST

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Check for and run optional user-supplied command to enable (advanced) customizations of the dev container
RUN if [ -n "${DEV_CONTAINER_USER_CMD_PRE}" ]; then echo "${DEV_CONTAINER_USER_CMD_PRE}" | sh ; fi

RUN groupadd vscode && useradd -rm -d /app -s /bin/bash -g vscode -u 1001 vscode

RUN apt-get update \
    && apt-get install python3 python3-pip -y \
    && apt-get install git -y 

RUN apt-get install locales -y \
    && locale-gen en_US.utf8

# Clean
RUN apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/* \

# Switch back to dialog for any ad-hoc use of apt-get
ENV DEBIAN_FRONTEND=dialog

# Configuring app / python requirements
WORKDIR /app
USER vscode

COPY requirements.txt /app/src/
RUN /usr/bin/pip3 install -r src/requirements.txt tox pytest

# Check for and run optional user-supplied command to enable (advanced) customizations of the dev container
RUN if [ -n "${DEV_CONTAINER_USER_CMD_POST}" ]; then echo "${DEV_CONTAINER_USER_CMD_POST}" | sh ; fi

# Preventing container from exiting
CMD tail -f /dev/null
