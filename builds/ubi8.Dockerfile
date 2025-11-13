#base_image needed for build tests on github. no need to adjust for end-user
arg base_image=ubi8
from ${base_image} as builder

run yum update -y && yum groupinstall -y 'Development Tools' \
    && yum install -y python3.12 git make wget unzip python3.12-devel cmake file

run cd /opt && git clone https://github.com/trendmicro/tlsh.git \
    && cd /opt/tlsh \
    && ./make.sh

run cd /opt \
    && wget https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz \
    && tar zxf ssdeep-2.14.1.tar.gz \
    && cd ssdeep-2.14.1 && ./configure \
    && make && make install

run python3.12 -m venv /eye && /eye/bin/pip install --upgrade pip && /eye/bin/pip install peyeon  

from ${base_image}
copy --from=builder /opt/tlsh/bin /opt/tlsh/bin
copy --from=builder /eye /eye
copy --from=builder /usr/local/bin/ssdeep /usr/local/bin/ssdeep

run yum update -y && yum install -y python3.12 file \
    && yum clean all

ENV PATH="/eye/bin:$PATH"

ENV PATH=/root/.local/bin:$PATH
