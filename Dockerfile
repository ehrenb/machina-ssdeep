FROM behren/machina-base-ubuntu:latest

# Install ssdeep library
# RUN cd /tmp && \
#     wget https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz && \
#     tar -zxvf ssdeep-2.14.1.tar.gz && \
#     cd ssdeep-2.14.1 && \
#     ./configure && \
#     make && \
#     make install && \
#     rm -rf /tmp/ssdeep-2.14.1

RUN apt update && \
    apt install -y build-essential \
                libffi-dev \
                libfuzzy-dev

COPY requirements.txt /tmp/
RUN pip3 install -r /tmp/requirements.txt
RUN rm /tmp/requirements.txt

COPY SSDeepAnalysis.json /schemas/

COPY src /machina/src
