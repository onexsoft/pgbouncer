make;make install;
ps -ef | grep pgbouncer | awk '{print $2}' | xargs kill -9
rm -rf /Users/April/work/log/pgbouncer/*
pgbouncer -v -d /usr/local/pgbouncer/config/pgbouncer.ini
ps -ef | grep pgbouncer
#psql -h 127.0.0.1 -p 1999 -U harris f_game;





