FROM cccs/assemblyline-v4-service-base:latest

# Set service to be run
ENV SERVICE_PATH pe_file.pe_file.PEFile

USER root

# Install apt dependancies
RUN apt update && apt install -y wget && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

# Install python dependancies
RUN pip install --user pefile signify pathlib2 ssdeep && rm -rf ~/.cache/pip

# Install APIScout dependancy from source
RUN pip install --user https://codeload.github.com/danielplohmann/apiscout/zip/master && rm -rf ~/.cache/pip

# Copy PEFile service code
WORKDIR /opt/al_service
COPY . .