# 
# Example Dockerfile for CI-CD
#
FROM python:3.14.4-slim-trixie

# --------------------------------------------
# Install strace and bubblewrap for pipcanary
#
RUN apt-get -q update && \
    apt-get -y -q install bubblewrap strace lz4

ARG USERNAME=leewok
ARG USER_UID=1111
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && apt-get update \
    && apt-get install -y sudo \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

ENV HOME=/home/$USERNAME
RUN chmod a+rwx $HOME

USER $USERNAME
WORKDIR $HOME

# --------------------------------------------
# Install Venv 
#
ENV VIRTUAL_ENV=$HOME/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN python3 -m venv $VIRTUAL_ENV && \ 
    pip install --upgrade pip

#---------------------------------------------
# Install SBOM generation tool
#
RUN pip install pipcanary==0.0.12 cyclonedx-bom~=7.3.0

COPY scan.sh .

#---------------------------------------------
# Run scans
#
CMD ["sudo", "-E", "bash", "scan.sh"]