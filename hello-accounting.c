/* hello-accounting.c based on: 
 * pam_tacplus.c - PAM interface for TACACS+ protocol.
 *
 * Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 * Jeroen Nijhof <jeroen@jeroennijhof.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 *
 * See `CHANGES' file for revision history.
 */



#include <stdio.h>

#include "pam_tacplus.h"
#include "support.h"

#include <stdlib.h>     /* malloc */
#include <stdio.h>
#include <syslog.h>
#include <netdb.h>      /* gethostbyname */
#include <sys/socket.h> /* in_addr */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>     /* va_ */
#include <signal.h>
#include <string.h>     /* strdup */
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>


int account(int tac_fd) {
	char buf[64];
	struct tac_attrib *attr;
	int retval;
	int type = TAC_PLUS_ACCT_FLAG_STOP;

	attr=(struct tac_attrib *)xcalloc(1, sizeof(struct tac_attrib));

	sprintf(buf, "%hu", getpid());
	tac_add_attrib(&attr, "task_id", buf);

	sprintf(buf, "%lu", (unsigned long)time(NULL));

	if (type == TAC_PLUS_ACCT_FLAG_START) {
	    tac_add_attrib(&attr, "start_time", buf);
	} else if (type == TAC_PLUS_ACCT_FLAG_STOP) {
	    tac_add_attrib(&attr, "stop_time", buf);
	}

	tac_add_attrib(&attr, "service", tac_service);

	if (tac_protocol != NULL && tac_protocol[0] != '\0')
	  tac_add_attrib(&attr, "protocol", tac_protocol);

	tac_add_attrib(&attr, "cmd", "hello-accounting");

	retval = tac_acct_send(tac_fd, type, "vyatta-dev", "pts/14", "", attr);

	/* this is no longer needed */
	tac_free_attrib(&attr);

	if(retval < 0) {
	    fprintf(stderr, "%s: send %s accounting failed\n",
	        __FUNCTION__,
	        tac_acct_flag2str(type));
	    close(tac_fd);
	    return -1;
	}

	struct areply re;
	if( tac_acct_read(tac_fd, &re) != TAC_PLUS_ACCT_STATUS_SUCCESS ) {
	    fprintf(stderr, "%s: reading accounting response (%s) failed\n",
	        __FUNCTION__,
	        tac_acct_flag2str(type));

	    if(re.msg != NULL)
	        free(re.msg);

	    close(tac_fd);
	    return -1;
	}

	if(re.msg != NULL)
	    free(re.msg);


	return 0;
}



int main(int argc, char **argv) {
	_pam_parse(argc, (const char **) argv);

	int srv_i;
	for(srv_i = 0; srv_i < tac_srv_no; srv_i++) {
		int tac_fd = tac_connect_single(tac_srv[srv_i].addr, tac_srv[srv_i].key, NULL);
		if (tac_fd < 0) {
		    fprintf(stderr, "%s: error connecting\n",
		        __FUNCTION__);
		    continue;
		}

		int retval = account(tac_fd);
		if (retval < 0) {
		    fprintf(stderr, "%s: error sending (acct)\n",
		        __FUNCTION__);
		}
		close(tac_fd);
	}
	return 0;
}

