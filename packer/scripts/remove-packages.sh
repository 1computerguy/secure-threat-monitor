#!/bin/sh

tdnf --assumeyes remove \
                 openldap \
                 cyrus-sasl \
                 serf \
                 subversion \
                 apr \
                 utf8proc \
                 apr-util \
                 subversion-perl \
                 python2-libs \
                 python2 perl \
                 perl-DBI \
                 perl-YAML \
                 perl-CGI \
                 git 

tdnf clean all