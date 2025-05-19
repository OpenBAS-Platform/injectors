
# Utilisation de l'image Python avec Alpine
FROM python:3.13-alpine

# Copier le code de l'injecteur Nuclei dans le conteneur
COPY src /opt/openbas-injector-nuclei

# Mise à jour des paquets et installation des dépendances nécessaires
RUN apk update && apk upgrade && \
    apk --no-cache add \
    curl \
    git \
    build-base \
    libmagic \
    libffi-dev \
    libxslt \
    libxslt-dev \
    libxml2 \
    libxml2-dev \
    && rm -rf /var/cache/apk/*

# Installation de Nuclei
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.4.3/nuclei_3.4.3_linux_amd64.zip -o nuclei.zip && \
    unzip nuclei.zip -d /usr/local/bin && \
    rm nuclei.zip

# Vérification de l'installation de Nuclei (optionnel)
RUN nuclei -version

# Mise à jour des templates Nuclei
RUN nuclei -update-templates

# Installation des dépendances Python
RUN cd /opt/openbas-injector-nuclei && \
    pip3 install --no-cache-dir -r requirements.txt

# Copier le script d'entrée (entrypoint)
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Définir l'ENTRYPOINT du conteneur
ENTRYPOINT ["/entrypoint.sh"]
