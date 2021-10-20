ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

# Set service to be run
ENV SERVICE_PATH pe_file.pe_file.PEFile

USER root
RUN apt-get update && apt-get install -y git

# Switch to assemblyline user
USER assemblyline

# Install python dependancies
RUN pip install --no-cache-dir --user pefile pillow signify>=0.4.0 pathlib2 ssdeep && rm -rf ~/.cache/pip

# Install APIScout dependancy from source
RUN pip install --no-cache-dir --user git+https://github.com/danielplohmann/apiscout.git && rm -rf ~/.cache/pip

# Copy PEFile service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
