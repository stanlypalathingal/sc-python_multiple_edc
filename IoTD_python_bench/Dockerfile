FROM arm32v7/python:3.7-slim-buster

RUN apt-get -q update && \
	apt-get -qy install \ 
	libatlas-base-dev \
	libgomp1

COPY requirements.txt ./requirements.txt
RUN pip3 install --no-cache-dir --extra-index-url=https://piwheels.org/simple -r requirements.txt 

ADD . /

EXPOSE 9003
RUN chmod a+x script.sh
ENTRYPOINT ["/bin/bash","script.sh"]

