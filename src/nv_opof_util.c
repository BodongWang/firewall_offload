/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <getopt.h>
#include <sys/stat.h>
#include <syslog.h>

#include "nv_opof.h"
#include "nv_opof_util.h"
#include "nv_opof_rpc.h"

static void *ss_sp = NULL;
static char *signals [] = {
	[SIGINT] = "SIGINT",
	[SIGILL] = "SIGILL",
	[SIGBUS] = "SIGBUS",
	[SIGFPE] = "SIGFPE",
	[SIGSEGV] = "SIGSEGV",
	[SIGTERM] = "SIGTERM",
	[_NSIG] = "MAXSIGNUM",
};

void nv_opof_log_open(void)
{
	openlog("nv_opof", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_USER);
}

void nv_opof_log_close(void)
{
	closelog();
}

void nv_opof_set_log_level(int level)
{
	setlogmask(LOG_UPTO(level));
}

static void
nv_opof_signal_handler(int signum, siginfo_t *info, void *ucontext)
{
	(void)info;
	(void)ucontext;
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		clean_up();
		kill(getpid(), signum);
		break;
	case SIGILL:
	case SIGBUS:
	case SIGFPE:
	case SIGSEGV:
	default:
		rte_exit(EXIT_FAILURE, "EAL: exit with error");
		abort(); /* We should not be here, coredump... */
	}
}

void nv_opof_signal_handler_install(void)
{
	int ret, i;
	stack_t ss;
	struct sigaction sa;

	ss_sp = calloc(1, SIGSTKSZ);
	if (!ss_sp) {
		log_error("cannot calloc signal handler stack");
		return;
	}
	ss.ss_sp = ss_sp;
	ss.ss_size = SIGSTKSZ;
	ss.ss_flags = 0;
	ret = sigaltstack(&ss, NULL);
	if (ret == -1) {
		log_error("cannot set sigalstack");
		goto out;
	}
	sa.sa_flags = SA_ONSTACK | SA_SIGINFO;
	sa.sa_sigaction = nv_opof_signal_handler;
	sigemptyset(&sa.sa_mask);
	for (i = 0; i < _NSIG; i++) {
		if (signals[i] == NULL)
			continue;
		ret = sigaction(i, &sa, NULL);
		if(ret == -1) {
			log_error("cannot install sighandler for %s",
				  signals[i]);
			goto out;
		}
	}
	return;

out:
	free(ss_sp);
	return;
}

void nv_opof_signal_handler_uninstall(void)
{
	struct sigaction sa;
	int i;

	if (ss_sp)
		free(ss_sp);
	ss_sp = NULL;
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	for (i = 0; i < _NSIG; i++) {
		if (signals[i] == NULL)
			continue;
		sigaction(i, &sa, NULL);
	}
}

int nv_opof_config_load(const char *file_path)
{
	char *buffer = NULL;
	FILE *fp = NULL;
	long lSize = 0;
	int ret = 0;

	fp = fopen(file_path, "rb");
	if (!fp) {
		log_info("No config file found, use default values");
		goto out;
	}

	fseek(fp, 0L, SEEK_END);
	lSize = ftell(fp);
	rewind(fp);

	/* allocate memory for entire content */
	buffer = calloc(1, lSize + 1);
	if (!buffer) {
		ret = ENOMEM;
		log_debug("Memory allocation failed");
		goto out_close;
	}

	/* copy the file into the buffer */
	if (1 != fread(buffer, lSize, 1, fp)) {
		ret = errno;
		log_debug("Read config file failed");
		goto out_free;
	}

	cJSON *jsoncfg = cJSON_Parse(buffer);
	if (!jsoncfg) {
		ret = EINVAL;
		log_error("Wrong config format");
		goto out_free;
	}

	cJSON *grpc_addr = cJSON_GetObjectItem(jsoncfg, "grpc_addr");
	cJSON *grpc_port = cJSON_GetObjectItem(jsoncfg, "grpc_port");
	if (grpc_addr && grpc_port) {
		snprintf(off_config_g.grpc_addr, GRPC_ADDR_SIZE, "%s",
			 grpc_addr->valuestring);
		off_config_g.grpc_port = grpc_port->valueint;
	}

out_free:
	free(buffer);
out_close:
	fclose(fp);
out:
	return ret;
}

