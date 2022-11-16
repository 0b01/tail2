#!/bin/sh

wget http://ports.ubuntu.com/dists/kinetic/universe/binary-arm64/Packages.gz
gzip -d < Packages.gz | grep "_arm64\.deb" | awk '{print "http://ports.ubuntu.com/"$2}' > out.list

sqlite3 syms.db <<EOF
CREATE TABLE url (
    id INTEGER PRIMARY KEY,
    url TEXT,
    complete INTEGER,
    UNIQUE(url)
);
CREATE TABLE file (
    id INTEGER PRIMARY KEY,
    url_id INTEGER,
    path TEXT,
    arch INTEGER,
    kind INTEGER,
    debug_id TEXT,
    FOREIGN KEY(url_id) REFERENCES url(id)
);
CREATE TABLE symbols (
    id INTEGER PRIMARY KEY,
    offset INTEGER,
    symbol TEXT,
    demangled TEXT,
    file_id INTEGER,
    FOREIGN KEY(file_id) REFERENCES file(id)
);
EOF
