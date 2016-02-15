sudo make install;
ps -ef | grep pgbouncer | awk '{print $2}' | xargs kill -9
rm -rf /home/huih/work/log/*
/usr/local/pgbouncer/bin/pgbouncer -v -d /usr/local/pgbouncer/config/pgbouncer.ini
ps -ef | grep pgbouncer

