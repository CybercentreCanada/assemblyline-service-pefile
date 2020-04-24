FROM cccs/assemblyline-v4-service-base:latest

# Set service to be run
ENV SERVICE_PATH pe_file.pe_file.PEFile

USER root

# Switch to assemblyline user
USER assemblyline

# Install python dependancies
RUN pip install --no-cache-dir --user pefile signify pathlib2 ssdeep && rm -rf ~/.cache/pip

# Install APIScout dependancy from source
RUN pip install --no-cache-dir --user https://codeload.github.com/danielplohmann/apiscout/zip/master && rm -rf ~/.cache/pip

# Copy PEFile service code
WORKDIR /opt/al_service
COPY . .