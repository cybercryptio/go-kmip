FROM python:3.9-slim

RUN pip install --no-cache-dir pykmip
COPY server.conf server.cert server.key /
CMD pykmip-server -f ./server.conf -l ./server.log
