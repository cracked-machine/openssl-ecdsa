FROM ubuntu:22.04

# this is our generic user
ARG USER=builder

# sudo for command line use
# git for vscode source control backend
RUN apt update -y && \
    DEBIAN_FRONTEND=noninteractive apt install -y \
    sudo \
    git \
    libssl-dev \
    cmake \
    build-essential \
    gdb \
    pkg-config

# add the generic user with same group/password for simplicity
RUN useradd -m $USER && echo "$USER:$USER" | chpasswd && adduser $USER sudo
# allow password-less sudo use
RUN echo "$USER           ALL = (ALL) NOPASSWD: ALL" >> /etc/sudoers

# set our generic user as default
USER $USER  

# default command
CMD /bin/bash