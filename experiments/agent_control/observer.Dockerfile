FROM python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

COPY observer-requirements.txt /tmp/observer-requirements.txt
RUN python -m pip --isolated install --no-cache-dir -r /tmp/observer-requirements.txt \
    && rm /tmp/observer-requirements.txt

USER 65532:65532
WORKDIR /tmp
