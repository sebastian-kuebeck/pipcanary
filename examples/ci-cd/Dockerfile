# 
# Example Dockerfile for CI-CD
#
FROM python:3.14.4-slim-bookworm

# --------------------------------------------
# Install strace and bubblewrap for pipcanary
#
RUN apt-get -q update && \
    apt-get -y -q install bubblewrap strace

# --------------------------------------------
# Install Venv 
#
ENV VIRTUAL_ENV=/opt/cienv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
RUN python3 -m venv $VIRTUAL_ENV && \ 
    pip install --upgrade pip

#---------------------------------------------
# Install analysis tools
#
RUN pip install pip-audit

# --------------------------------------------
# Install PipCanary from PyPi
# RUN pip install pipcanary

# --------------------------------------------
# Install PipCanary from wheel
# 
ARG WHEEL=pipcanary-0.0.7-py3-none-any.whl
ADD ${WHEEL} .
RUN pip install ${WHEEL}

COPY requirements.txt requirements.txt

#---------------------------------------------
# Run scans
#
CMD ["sh", "-c", "pipcanary -r requirements.txt"]
