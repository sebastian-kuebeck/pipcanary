# 
# Example Dockerfile for CI-CD
#
FROM python:3.14.4-slim-trixie

# --------------------------------------------
# Install strace and bubblewrap for pipcanary
#
RUN apt-get -q update && \
    apt-get -y -q install bubblewrap strace lz4

# --------------------------------------------
# Install Venv 
#
ENV VIRTUAL_ENV=/opt/cienv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN python3 -m venv $VIRTUAL_ENV && \ 
    pip install --upgrade pip

#---------------------------------------------
# Install SBOM generation tool
#
RUN pip install cyclonedx-bom~=7.3.0

# --------------------------------------------
# Install PipCanary from wheel
# 
ARG WHEEL=pipcanary-x.y.z-py3-none-any.whl
ADD ${WHEEL} .
RUN pip install ${WHEEL}

COPY scan.sh .

#---------------------------------------------
# Run scans
#
CMD ["bash", "scan.sh"]