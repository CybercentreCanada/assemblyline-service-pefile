FROM cccs/assemblyline-v4-service-base:latest

# Set service to be run
ENV SERVICE_PATH pe_file.pe_file.PEFile

# Install python dependancies
RUN pip install pefile signify pathlib2 ssdeep

# Install APIScout dependancy from source
RUN wget -O /tmp/apiscout-master.zip https://codeload.github.com/danielplohmann/apiscout/zip/master
RUN pip install /tmp/apiscout-master.zip

# Cleanup temp
RUN rm -rf /tmp/apiscout-master.zip

# Switch to assemblyline user
USER assemblyline

# Copy PEFile service code
WORKDIR /opt/al_service
COPY . .