from ubi8 as builder

run yum update -y && yum groupinstall -y 'Development Tools' \
    && yum install -y python3.12 git make wget unzip python3.12-devel cmake file

# run dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm \
#    && yum install -y file-libs

run cd /opt && git clone https://github.com/trendmicro/tlsh.git \
    && cd /opt/tlsh \
    && ./make.sh

run cd /opt \
    && wget https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz \
    && tar zxf ssdeep-2.14.1.tar.gz \
    && cd ssdeep-2.14.1 && ./configure \
    && make && make install


run python3.12 -m venv /eye && /eye/bin/pip install peyeon  


from ubi8
copy --from=builder /opt/tlsh/bin /opt/tlsh/bin
copy --from=builder /eye /eye
copy --from=builder /usr/local/bin/ssdeep /usr/local/bin/ssdeep

arg USER_ID
arg OUN

run yum update -y && yum install -y python3.12 file \
    && yum clean all

RUN groupadd -g $USER_ID $OUN \
    && useradd -ms /bin/bash $OUN -u $USER_ID -g $USER_ID

RUN chown -R $OUN /eye
USER $OUN
ENV PATH="/eye/bin:$PATH"

ENV PATH=/home/$OUN/.local/bin:$PATH

