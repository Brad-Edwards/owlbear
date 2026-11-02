# Supply an approved digest-pinned Python >=3.12 image; no default floating tag.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
COPY wheelhouse/ /wheelhouse/
# requirements.lock pins and hashes every transitive wheel, including this adapter.
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheelhouse \
    --require-hashes -r /wheelhouse/requirements.lock
USER 65532:65532
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-I", "-B", "-m", "bigrae_adapter_sdk.worker"]
