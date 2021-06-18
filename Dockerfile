ARG BASEIMAGE=alpine:3.14.0
FROM ${BASEIMAGE}
ARG WORKDIR=/iq-casc
WORKDIR ${WORKDIR}
COPY . .
RUN apk add --no-cache python3 py3-pip && \
    ln -sf ${WORKDIR}/iq-apply-conf.py /usr/local/bin/iq-apply-conf && \
    ln -sf ${WORKDIR}/iq-healthcheck.py /usr/local/bin/iq-healthcheck && \
    ln -sf ${WORKDIR}/iq-scrape-conf.py /usr/local/bin/iq-scrape-conf
CMD [ "/bin/sh" ]
