ARG BASEIMAGE=python:3-alpine3.13
FROM ${BASEIMAGE}

ARG WORKDIR=/iqcasc
ARG USER=iqcasc
ARG USER_ID=1000
ARG GROUP=iqcasc
ARG GROUP_ID=1000

ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${WORKDIR}/.local/bin

WORKDIR ${WORKDIR}
COPY . .
RUN addgroup -S -g ${GROUP_ID} ${GROUP} && \
    adduser -S -D -g "" -h ${WORKDIR} -u ${USER_ID} -G ${GROUP} ${USER} && \
    ln -sf ${WORKDIR}/iq-apply-conf.py /usr/local/bin/iq-apply-conf && \
    ln -sf ${WORKDIR}/iq-healthcheck.py /usr/local/bin/iq-healthcheck && \
    ln -sf ${WORKDIR}/iq-scrape-conf.py /usr/local/bin/iq-scrape-conf && \
    chown -R ${USER_ID}:${GROUP_ID} ${WORKDIR}

USER ${USER}
RUN pip3 install --no-cache-dir --user requests
CMD [ "/bin/sh" ]
