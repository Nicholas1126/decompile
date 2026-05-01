FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Route apt downloads through local proxy on macOS host (192.168.65.2:3128)
# which has direct access to mirrors blocked from Docker's VM network.
# Use sg.archive.ubuntu.com (Singapore mirror, accessible from host).
RUN printf 'deb [trusted=yes] http://sg.archive.ubuntu.com/ubuntu jammy main restricted universe multiverse\n\
deb [trusted=yes] http://sg.archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse\n\
deb [trusted=yes] http://sg.archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse\n\
deb [trusted=yes] http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse\n' \
    > /etc/apt/sources.list \
    && printf 'Acquire::http::Proxy "http://192.168.65.2:3128";\nAcquire::Retries "3";\n' \
    > /etc/apt/apt.conf.d/80proxy \
    && rm -f /etc/apt/apt.conf.d/docker-clean

# --- Base packages ---
RUN apt-get update || true; \
    apt-get install -y --no-install-recommends --allow-unauthenticated \
    wget curl unzip git python3 python3-pip xz-utils binutils \
    && rm -rf /var/lib/apt/lists/*

# --- JDK 21 (Ghidra 11.2+ requires JDK 21) ---
RUN apt-get update || true; \
    apt-get install -y --no-install-recommends --allow-unauthenticated \
    openjdk-21-jdk-headless libharfbuzz0b libfreetype6 fontconfig \
    && rm -rf /var/lib/apt/lists/*
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

# --- .NET SDK 8.0 (needed at runtime for ilspy-cli SelfContained=false) ---
RUN apt-get update || true; \
    apt-get install -y --no-install-recommends --allow-unauthenticated dotnet-sdk-8.0 \
    && rm -rf /var/lib/apt/lists/*
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

# --- ILSpy CLI (pre-built for linux-x64, built outside Docker due to seccomp restriction) ---
COPY ilspy-prebuilt/ /opt/ilspy-cli/
RUN chmod +x /opt/ilspy-cli/ilspy-cli
ENV PATH="/opt/ilspy-cli:${PATH}"

# --- Ghidra 11.2.1 (pre-downloaded to avoid Docker network issues) ---
ENV GHIDRA_VERSION=11.2.1
ENV GHIDRA_DIR=/opt/ghidra
COPY docker-downloads/ghidra.zip /tmp/ghidra.zip
RUN unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_DIR} \
    && rm /tmp/ghidra.zip
ENV PATH="${GHIDRA_DIR}/support:${PATH}"

# Pre-configure Ghidra JDK path so headless mode works without TTY
RUN sed -i 's|JAVA_HOME="$(java -cp "${LS_CPATH}" LaunchSupport "${INSTALL_DIR}" ${JAVA_TYPE_ARG} -save)"|if [ -n "$JAVA_HOME" ]; then echo "Using JAVA_HOME=$JAVA_HOME"; else JAVA_HOME="$(java -cp "${LS_CPATH}" LaunchSupport "${INSTALL_DIR}" ${JAVA_TYPE_ARG} -save)"; fi|' "${GHIDRA_DIR}/support/launch.sh"

# --- CFR 0.152 (pre-downloaded) ---
COPY docker-downloads/cfr.jar /opt/cfr.jar

# --- RetDec (pre-downloaded) ---
COPY docker-downloads/retdec.tar.xz /tmp/retdec.tar.xz
RUN mkdir -p /opt/retdec \
    && tar -xf /tmp/retdec.tar.xz -C /opt/retdec \
    && rm /tmp/retdec.tar.xz
ENV PATH="/opt/retdec/bin:${PATH}"

# --- .NET Framework reference assemblies for ILSpy (pre-downloaded) ---
COPY docker-downloads/netfx.nupkg /tmp/netfx.nupkg
RUN mkdir -p /usr/lib/mono/4.7.2-api \
    && unzip -q /tmp/netfx.nupkg -d /tmp/netfx \
    && cp -r /tmp/netfx/build/.NETFramework/v4.7.2/. /usr/lib/mono/4.7.2-api/ \
    && for v in 4.0-api 4.5-api 4.5.1-api 4.5.2-api 4.6-api 4.6.1-api 4.6.2-api 4.7-api 4.7.1-api; do ln -sf /usr/lib/mono/4.7.2-api /usr/lib/mono/$v; done \
    && rm -rf /tmp/netfx.nupkg /tmp/netfx

# --- Ghidra export script ---
RUN mkdir -p ${GHIDRA_DIR}/ghidra_scripts
COPY ghidra_scripts/ExportDecompiled.java ${GHIDRA_DIR}/ghidra_scripts/

# --- Python wrapper ---
COPY decompile.py /opt/decompile.py
RUN chmod +x /opt/decompile.py

# --- Working directory ---
WORKDIR /data

ENTRYPOINT ["python3", "/opt/decompile.py"]
