FROM python:3.8-alpine

LABEL name="Python dnstap receiver" \
      description="Dnstap streams receiver" \
      url="https://github.com/dmachard/dnstap-receiver" \
      maintainer="d.machard@gmail.com"
      
WORKDIR /home/dnstap

COPY . /home/dnstap/

RUN true \
    && apk update \
    && apk add gcc musl-dev \
    && adduser -D dnstap \
    && pip install --no-cache-dir protobuf pyyaml aiohttp geoip2 tlds cachetools\
    && apk del gcc musl-dev \
    && cd /home/dnstap \
    && mkdir -p /home/dnstap/logs/ \
    && sed -i 's/local-address: 127.0.0.1/local-address: 0.0.0.0/g' ./dnstap_receiver/dnstap.conf \
    && chown -R dnstap:dnstap /home/dnstap \
    && true
    
USER dnstap

EXPOSE 6000/tcp
EXPOSE 8080/tcp

ENTRYPOINT ["python", "-c", "from dnstap_receiver.receiver import start_receiver; start_receiver()"]