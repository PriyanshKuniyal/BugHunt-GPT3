# Use official Python image
FROM python:3.10

# Set working dir and install Python deps
WORKDIR /app
# First copy ONLY requirements.txt
COPY requirements.txt ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install git (if not already in your base image)
RUN apt-get update && apt-get install -y --no-install-recommends git

# Clone Toxssin repository to /app/toxssin directory
RUN git clone https://github.com/t3l3machus/toxssin.git /app/toxssin

# Install Toxssin's Python dependencies
RUN pip install --no-cache-dir -r /app/toxssin/requirements.txt

# Make the main script executable (optional)
RUN chmod +x /app/toxssin/toxssin.py

# Create a symlink for easy access (optional)
RUN ln -s /app/toxssin/toxssin.py /usr/local/bin/toxin

# Install sqlmap and dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Create shared memory directory
RUN mkdir -p /dev/shm && chmod 1777 /dev/shm
# Copy rest of the project

COPY . /app
EXPOSE 8080
CMD ["python", "main.py"]

