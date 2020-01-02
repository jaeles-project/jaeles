FROM ubuntu

RUN apt-get update -y; apt-get install golang git -y; go get -u github.com/jaeles-project/jaeles; /root/go/bin/jaeles config -a init

WORKDIR /root/go/bin/

VOLUME /root/go/bin/out

EXPOSE 5000

CMD [ "/root/go/bin/jaeles", "server", "--host", "0.0.0.0" ]
