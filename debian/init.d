#!/bin/sh
#		Written by Miquel van Smoorenburg <miquels@cistron.nl>.
#		Modified for Debian
#		by Ian Murdock <imurdock@gnu.ai.mit.edu>.
#
# Version:	@(#)skeleton  1.9  26-Feb-2001  miquels@cistron.nl
# /etc/init.d/dns-flood-detector: v1 2006/11/03 Jan Wagner <waja@cyconet.org>

### BEGIN INIT INFO
# Provides: dns-flood-detector
# Required-Start: $local_fs $network $remote_fs $syslog
# Required-Stop: $local_fs $network $remote_fs $syslog
# Default-Start:  2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: start and stop the dns-flood-detector daemon
# Description:  detect abusive usage levels on high traffic nameservers
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/bin/dns-flood-detector
NAME=dns-flood-detector
DESC=dns-flood-detector

test -x $DAEMON || exit 0

. /lib/lsb/init-functions

# Include dns-flood-detector defaults if available
if [ -f /etc/default/dns-flood-detector ] ; then
	. /etc/default/dns-flood-detector
fi

set -e

case "$1" in
  start)
	echo -n "Starting $DESC: "
	start-stop-daemon --start --quiet --pidfile /var/run/$NAME.pid \
		--exec $DAEMON -- $DAEMON_OPTS
	/bin/pidof $DAEMON > /var/run/$NAME.pid
	echo "$NAME."
	;;
  stop)
	echo -n "Stopping $DESC: "
	start-stop-daemon --stop --quiet --pidfile /var/run/$NAME.pid \
		--exec $DAEMON
	echo "$NAME."
	;;
  restart|force-reload)
	echo -n "Restarting $DESC: "
	start-stop-daemon --stop --quiet --pidfile \
		/var/run/$NAME.pid --exec $DAEMON
	start-stop-daemon --start --quiet --pidfile \
		/var/run/$NAME.pid --exec $DAEMON -- $DAEMON_OPTS
	/bin/pidof $DAEMON > /var/run/$NAME.pid
	echo "$NAME."
	;;
  *)
	N=/etc/init.d/$NAME
	# echo "Usage: $N {start|stop|restart|reload|force-reload}" >&2
	echo "Usage: $N {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
