# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory in the container to /home/vscode
WORKDIR /home/vscode

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    ssh \
    less \
    build-essential \
    awscli \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Ansible and related tools
RUN pip install --no-cache-dir \
    ansible==12.1.0 \
    ansible-lint==4.3.0 \
    molecule==25.9.0 \
    docker==7.1.0 \
    molecule[docker] \
    boto3==1.40.59 \
    ec2instanceconnectcli==1.0.3


# Install amazon.aws collection
RUN ansible-galaxy collection install amazon.aws -p /usr/share/ansible/collections

# Set up non-root user for VSCode
RUN groupadd --gid 1000 vscode \
    && useradd --uid 1000 --gid 1000 -m vscode \
    && mkdir -p /home/vscode/.vscode-server/extensions \
    && chown -R vscode:vscode /home/vscode

# Make sure the non-root user has the rights to use sudo without password
RUN echo "vscode ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Switch to non-root user
USER vscode
# Set environment variables for non-root user
ENV PATH="/home/vscode/.local/bin:${PATH}"

# Default command when container starts
CMD ["/bin/bash"]