/*
 * exim-p0f3-dlfunc.c - p0f version 3 dlfunc for Exim
 *
 * Copyright (C) 2012 Janne Snabb <snabb@epipe.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * This work is based on p0f-client.c and api.h as distributed with
 * p0f version 3.05b.
 *
 * Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>
 *
 * Distributed under the terms and conditions of GNU LGPL.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* Exim4 dlfunc API header: */
#include "local_scan.h"

/*****************************************************************************
 * Configuration settings:
 *****************************************************************************/

/* timeout for p0f socket read and write operations in seconds: */
#define P0F_SOCKET_TIMEOUT	5

/* default string which is returned when p0f did not recognize the OS: */
#define P0F_OS_UNKNOWN		US"(unknown)"

/* default string which is returned when p0f did not have information about
 * the host: */
#define P0F_OS_LOOKUP_NOMATCH	US"(not found)"

/* default string which is returned when there was a lookup failure of some
 * sort: */
#define P0F_OS_LOOKUP_FAILED	US"(failed)"

/*****************************************************************************
 * p0f v3 protocol (from p0f api.h, included here for convenience):
 *****************************************************************************/

#define P0F3_QUERY_MAGIC	0x50304601
#define P0F3_RESP_MAGIC		0x50304602

#define P0F3_STATUS_BADQUERY	0x00
#define P0F3_STATUS_OK		0x10
#define P0F3_STATUS_NOMATCH	0x20

#define P0F3_ADDR_IPV4		0x04
#define P0F3_ADDR_IPV6		0x06

#define P0F3_STR_MAX		31

#define P0F3_MATCH_FUZZY	0x01
#define P0F3_MATCH_GENERIC	0x02

/* Keep these structures aligned to avoid architecture-specific padding. */

struct p0f3_api_query {
	uint32_t	magic;		/* Must be P0F3_QUERY_MAGIC	*/
	uint8_t		addr_type;	/* P0F3_ADDR_*			*/
	uint8_t		addr[16];	/* IP (big endian left align)	*/
};

struct p0f3_api_response {
	uint32_t	magic;		/* Must be P0F3_RESP_MAGIC	*/
	uint32_t	status;		/* P0F3_STATUS_*		*/

	uint32_t	first_seen;	/* First seen (unix time)	*/
	uint32_t	last_seen;	/* Last seen (unix time)	*/
	uint32_t	total_conn;	/* Total connections seen	*/

	uint32_t	uptime_min;	/* Last uptime (minutes)	*/
	uint32_t	up_mod_days;	/* Uptime modulo (days)		*/

	uint32_t	last_nat;	/* NAT / LB last detected	*/
	uint32_t	last_chg;	/* OS chg last detected		*/

	int16_t		distance;	/* System distance		*/

	uint8_t		bad_sw;		/* Lying about U-A / Server	*/
	uint8_t		os_match_q;	/* Match quality		*/

	uint8_t		os_name[P0F3_STR_MAX + 1];	/* Name of OS	*/
	uint8_t		os_flavor[P0F3_STR_MAX + 1];	/* Flavor of OS	*/

	uint8_t		http_name[P0F3_STR_MAX + 1];	/* Name of HTTP app */
	uint8_t		http_flavor[P0F3_STR_MAX + 1];	/* Flavor of HTTP app */

	uint8_t		link_type[P0F3_STR_MAX + 1];	/* Link type	*/

	uint8_t		language[P0F3_STR_MAX + 1];	/* Language	*/
};

/*****************************************************************************
 * p0f os lookup function:
 *****************************************************************************/

int
p0f3_os(uschar **yield, int argc, uschar *argv[])
{
	struct	p0f3_api_query		q;
	struct	p0f3_api_response	r;

	struct	sockaddr_un		sun;

	int	s;
	ssize_t	ret;

	if (argc != 2) {
		*yield = string_copy(US"Invalid number of arguments.");
		return ERROR;
	}

	if (strlen(argv[0]) >= sizeof sun.sun_path - 1) { /* - 1 for \0 */
		*yield = string_copy(US"Socket path is too long.");
		return ERROR;
	}

	/* setup query structure: */

	memset(&q, 0, sizeof q);
	q.magic = P0F3_QUERY_MAGIC;

	if (inet_pton(AF_INET, (char *) argv[1], q.addr) == 1) {
		q.addr_type = P0F3_ADDR_IPV4;
	} else if (inet_pton(AF_INET6, (char *) argv[1], q.addr) == 1) {
		q.addr_type = P0F3_ADDR_IPV6;
	} else {
		*yield = string_copy(US"Unrecognized address format.");
		return FAIL;
	}

	/* setup query socket: */

	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		*yield = string_sprintf(US"Call to socket() failed"
					" (errno = %d).", errno);
		return FAIL;
	}

	memset(&sun, 0, sizeof sun);
	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, argv[0]);
	/* Note: We ignore sun.sun_len which only exists on some platforms.
	 * It is poorly documented and ignored by most(?) OSes anyway. */

	if (connect(s, (struct sockaddr *) &sun, sizeof sun) != 0) {
		log_write(0, LOG_MAIN, US"p0f: Can't connect to API socket %s"
			  " (errno = %d)."
			  " p0f daemon down or socket name incorrect?",
			  argv[0], errno);
		*yield = string_copy(P0F_OS_LOOKUP_FAILED);
		close(s);
		return OK;
	}

	/* do query: */

	alarm(P0F_SOCKET_TIMEOUT);	/* exim hopefully catches SIGALRM */
	ret = write(s, &q, sizeof q);
	alarm(0);
	if (ret != sizeof q) {
		if (ret < 0)
			log_write(0, LOG_MAIN,
				  US"p0f: Error %d writing to API socket.",
				  errno);
		else
			log_write(0, LOG_MAIN,
				  US"p0f: Short write to API socket.");

		*yield = string_copy(P0F_OS_LOOKUP_FAILED);
		close(s);
		return OK;
	}

	alarm(P0F_SOCKET_TIMEOUT);	/* exim hopefully catches SIGALRM */
	ret = read(s, &r, sizeof r);
	alarm(0);
	if (ret != sizeof r) {
		if (ret < 0)
			log_write(0, LOG_MAIN,
				  US"p0f: Error %d reading from API socket.",
				  errno);
		else
			log_write(0, LOG_MAIN,
				  US"p0f: Short read from API socket.");

		*yield = string_copy(P0F_OS_LOOKUP_FAILED);
		close(s);
		return OK;
	}
	close(s);

	/* check response status: */

	if (r.magic != P0F3_RESP_MAGIC) {
		log_write(0, LOG_MAIN, US"p0f: Bad response magic.");
		*yield = string_copy(P0F_OS_LOOKUP_FAILED);
		return OK;
	}

	if (r.status == P0F3_STATUS_BADQUERY) {
		log_write(0, LOG_MAIN, US"p0f: We were misunderstood.");
		*yield = string_copy(P0F_OS_LOOKUP_FAILED);
		return OK;
	}

	if (r.status == P0F3_STATUS_NOMATCH) {
		*yield = string_copy(P0F_OS_LOOKUP_NOMATCH);
		return OK;
	}

	/* produce output for unknown OS: */

	if (r.os_name[0] == '\0') {
		*yield = string_copy(P0F_OS_UNKNOWN);
		return OK;
	}

	/* output detected OS: */

	if (r.os_flavor[0] == '\0') {
		*yield = string_copy(r.os_name);
	} else {
		*yield = string_sprintf("%s %s", r.os_name, r.os_flavor);
	}
	return OK;
}

/*****************************************************************************
 * eof
 *****************************************************************************/
