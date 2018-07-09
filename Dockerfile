FROM alpine:3.6

RUN set -xe \
    && apk update \
    && apk upgrade \
    && apk add --update \
    && apk add samba \
    && apk add samba-common-tools \
    && apk add supervisor \
    && apk add python \
    && apk add python-dev \
    && apk add py-pip \
    #&& apk add build-base \
    #&& apk add vim \
    && apk add nmap \
    && pip install --upgrade pip \
    && pip install python-nmap \
    && pip install openpyxl \
    && pip install requests \
    && pip install flask \
    #&& pip install BeautifulSoup4 \
    && pip install pymongo \
    && rm -rf /var/cache/apk/* \
    && mkdir /config /scan_code /shared /web_code \
    && chmod 777 /shared \
    && chmod 777 /web_code \
    && chmod 777 /scan_code

VOLUME /scan_code /shared /web_code
COPY *.conf /config/
COPY /scan_code/*.py /scan_code
COPY /scan_code/nselib /usr/share/nmap/nselib
COPY /scan_code/scripts /usr/share/nmap/scripts
COPY /scan_code/nse_main.lua /usr/share/nmap
COPY /web_code /web_code/
COPY collection.py /usr/lib/python2.7/site-packages/pymongo/collection.py

EXPOSE 137/udp 138/udp 139 445 5200

ENTRYPOINT ["supervisord", "-c", "/config/supervisord.conf"]

#Reference pwntr/samba-alpine
