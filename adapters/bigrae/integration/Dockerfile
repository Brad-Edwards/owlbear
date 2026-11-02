ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
RUN apt-get update -qq && apt-get install -y --no-install-recommends gcc libc6-dev libssl-dev binutils
COPY wheelhouse /wheelhouse
RUN python -m pip install --no-index --find-links=/wheelhouse --require-hashes -r /wheelhouse/requirements.lock
COPY source /source
ENTRYPOINT ["python", "/source/integration/guest_test.py"]
