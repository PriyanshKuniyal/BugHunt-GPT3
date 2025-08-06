# Use official Python image
FROM python:3.10

# Set working dir and install Python deps
WORKDIR /app
# First copy ONLY requirements.txt
COPY requirements.txt ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt


# Install sqlmap and dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Create shared memory directory
RUN mkdir -p /dev/shm && chmod 1777 /dev/shm
# Copy rest of the project
COPY . /app