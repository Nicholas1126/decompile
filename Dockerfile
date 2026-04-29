FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# --- Base packages ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl unzip git python3 python3-pip xz-utils \
    && rm -rf /var/lib/apt/lists/*

# --- JDK 21 (Ghidra 11.2+ requires JDK 21) ---
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-21-jdk-headless \
    && apt-get install -y --no-install-recommends libharfbuzz0b libfreetype6 fontconfig \
    && rm -rf /var/lib/apt/lists/*
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# --- .NET SDK 8.0 (build ilspy-cli) ---
RUN apt-get update && apt-get install -y --no-install-recommends dotnet-sdk-8.0 \
    && rm -rf /var/lib/apt/lists/*
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

# --- Build ILSpy CLI from source ---
COPY ilspy-cli/ /tmp/ilspy-cli/
RUN cd /tmp/ilspy-cli \
    && dotnet publish -c Release -o /opt/ilspy-cli \
    && rm -rf /tmp/ilspy-cli
ENV PATH="/opt/ilspy-cli:${PATH}"

# --- Ghidra 11.2.1 ---
ENV GHIDRA_VERSION=11.2.1
ENV GHIDRA_DIR=/opt/ghidra
RUN curl -fsSL -o ghidra.zip "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_20241105.zip" \
    && unzip -q ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_DIR} \
    && rm ghidra.zip
ENV PATH="${GHIDRA_DIR}/support:${PATH}"

# Pre-configure Ghidra JDK path so headless mode works without TTY
RUN sed -i 's|JAVA_HOME="$(java -cp "${LS_CPATH}" LaunchSupport "${INSTALL_DIR}" ${JAVA_TYPE_ARG} -save)"|if [ -n "$JAVA_HOME" ]; then echo "Using JAVA_HOME=$JAVA_HOME"; else JAVA_HOME="$(java -cp "${LS_CPATH}" LaunchSupport "${INSTALL_DIR}" ${JAVA_TYPE_ARG} -save)"; fi|' "${GHIDRA_DIR}/support/launch.sh"

# --- CFR 0.152 ---
ENV CFR_VERSION=0.152
RUN curl -fsSL -o /opt/cfr.jar "https://github.com/leuschner/cfr/releases/download/CFR_${CFR_VERSION}/cfr-${CFR_VERSION}.jar" \
    || curl -fsSL -o /opt/cfr.jar "https://www.benf.org/other/cfr/cfr-${CFR_VERSION}.jar"

# --- RetDec (optional fallback for native binaries) ---
RUN (curl -fsSL -o retdec.tar.xz "https://github.com/avast/retdec/releases/download/v5.0/RetDec-v5.0-Linux-Release.tar.xz" \
    && tar -xf retdec.tar.xz -C /opt \
    && mv /opt/RetDec /opt/retdec \
    && rm retdec.tar.xz) \
    || echo "RetDec skipped, Ghidra is primary"
ENV PATH="/opt/retdec/bin:${PATH}"

# --- Ghidra export script ---
RUN mkdir -p ${GHIDRA_DIR}/ghidra_scripts
COPY ghidra_scripts/ExportDecompiled.java ${GHIDRA_DIR}/ghidra_scripts/

# --- Python wrapper ---
COPY decompile.py /opt/decompile.py
RUN chmod +x /opt/decompile.py

# --- Working directory ---
WORKDIR /data

ENTRYPOINT ["python3", "/opt/decompile.py"]
