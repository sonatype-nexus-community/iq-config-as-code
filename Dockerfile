ARG BASEIMAGE=python:3-alpine3.14
FROM ${BASEIMAGE}

ARG WORKDIR=/data
ARG APPDIR=/iqcasc
ARG USER=iqcasc
ARG USER_ID=1000
ARG GROUP=iqcasc
ARG GROUP_ID=1000

ENV PATH=${PATH}:${APPDIR}/.local/bin

WORKDIR ${WORKDIR}
WORKDIR ${APPDIR}
COPY . .
RUN addgroup -S -g ${GROUP_ID} ${GROUP} && \
    adduser -S -D -g "" -h ${APPDIR} -u ${USER_ID} -G ${GROUP} ${USER} && \
    ln -sf ${APPDIR}/iq-config-as-code/iq-apply-conf.py /usr/local/bin/iq-apply-conf && \
    ln -sf ${APPDIR}/iq-config-as-code/iq-healthcheck.py /usr/local/bin/iq-healthcheck && \
    ln -sf ${APPDIR}/iq-config-as-code/iq-scrape-conf.py /usr/local/bin/iq-scrape-conf && \
    chown -R ${USER_ID}:${GROUP_ID} ${APPDIR} ${WORKDIR} && \
    apk add --no-cache git

USER ${USER}
RUN pip3 install --no-cache-dir --user requests
WORKDIR ${WORKDIR}
CMD [ "/bin/sh" ]
