// SPDX-License-Identifier: BSD-3-Clause

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <wait.h>

#include "ipc.h"
#include "server.h"

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

static int server_fd;
static int client_fd;

static void cleanup()
{
	puts("\nClosing server...");
	while (waitpid(-1, NULL, 0) > 0)
		;
	close_socket(server_fd);
	close_socket(client_fd);
	int ret = remove(SOCKET_NAME);
	if (ret == -1) {
		perror("remove");
		exit(-1);
	}

	exit(0);
}

static void handle_sigint()
{
	cleanup();
}

static void quit(int status)
{
	cleanup();
	exit(status);
}

static int lib_prehooks(struct lib *lib)
{
	/* Create outputfile name. */
	lib->outputfile = malloc(sizeof(OUTPUT_TEMPLATE));
	if (!lib->outputfile) {
		perror("malloc");
		return -1;
	}
	strncpy(lib->outputfile, OUTPUT_TEMPLATE, sizeof(OUTPUT_TEMPLATE));

	/* Create outputfile. */
	int outfile = mkstemp(lib->outputfile);
	if (outfile == -1) {
		perror("mkstemp");
		return -1;
	}

	return 0;
}

void print_error(struct lib *lib)
{
	FILE *fp = fopen(lib->outputfile, "wt");
	char error_buffer[BUFSIZ] = {0};
	sprintf(error_buffer, "Error: %s ", lib->libname);
	if (strlen(lib->funcname) > 0) {
		strcat(error_buffer, lib->funcname);
		strcat(error_buffer, " ");

		if (strlen(lib->filename) > 0) {
			strcat(error_buffer, lib->filename);
			strcat(error_buffer, " ");
		}
	}

	fprintf(fp, "%scould not be executed.\n", error_buffer);
	fclose(fp);
	send(client_fd, lib->outputfile, strlen(lib->outputfile), 0);
	close_socket(client_fd);
}

static int lib_load(struct lib *lib)
{
	lib->handle = dlopen(lib->libname, RTLD_LAZY);

	if (!lib->handle) {
		perror("dlopen");
		print_error(lib);
		return -1;
	}

	(void)dlerror();
	void *addr = dlsym(lib->handle, lib->funcname);

	if (!addr) {
		FILE *fp = fopen(lib->outputfile, "wt");
		print_error(lib);
		return -1;
	}

	if (lib->filename) {
		lib->p_run = addr;
	} else {
		lib->run = addr;
	}
	return 0;
}

static int lib_execute(struct lib *lib)
{
	if (lib->filename) {
		int fd = open(lib->outputfile, O_WRONLY | O_TRUNC);
		fflush(stdout);
		int back = dup(STDOUT_FILENO);
		dup2(fd, STDOUT_FILENO);
		lib->p_run(lib->filename);
		fflush(stdout);
		dup2(back, STDOUT_FILENO);
		close(back);

	} else {
		lib->run();
	}

	return 0;
}

static int lib_close(struct lib *lib)
{
	dlclose(lib->handle);
	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;

	ret = sscanf(buf, "%s %s %s", name, func, params);
	if (ret < 0)
		return -1;

	return ret;
}

void handle_client(int client_fd)
{
	char buf[BUFSIZE] = {0};

	if (recv_socket(client_fd, buf, BUFSIZE) < 0) {
		perror("recv err");
		quit(-1);
	}

	char name[BUFSIZ] = {0};
	char func[BUFSIZ] = {0};
	char params[BUFSIZ] = {0};

	parse_command(buf, name, func, params);
	strcpy(buf, "");

	if (strlen(func) == 0) {
		strcpy(func, "run");
	}

	struct lib lib = {.libname = name, .funcname = func, .filename = params};

	if (lib_run(&lib) < 0) {
		perror("run err");
		quit(-1);
	}

	if (send_socket(client_fd, lib.outputfile, strlen(lib.outputfile)) < 0) {
		perror("send err");
		quit(-1);
	}

	close_socket(client_fd);
}

void init_server(struct sockaddr_un *addr, socklen_t addrlen)
{
	/* Trap Ctrl+C signal. */
	signal(SIGINT, handle_sigint);
	signal(SIGHUP, handle_sigint);
	signal(SIGTERM, handle_sigint);

	int opt = 1;
	server_fd = create_socket();

	/* Initialize socket address. */
	memset(addr, 0, addrlen);
	addr->sun_family = AF_UNIX;
	strncpy(addr->sun_path, SOCKET_NAME, sizeof(addr->sun_path) - 1);

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
		perror("setsockopt");
		quit(EXIT_FAILURE);
	}

	int ret = bind(server_fd, (struct sockaddr *)addr, addrlen);
	if (ret == -1) {
		perror("bind");
		quit(-1);
	}

	if (listen(server_fd, MAX_CLIENTS) < 0) {
		perror("listen");
		quit(-1);
	}
}

int main(void)
{
	struct sockaddr_un addr;
	socklen_t addrlen = sizeof(addr);
	init_server(&addr, addrlen);

	while (1) {
		int new_client_fd =
			accept(server_fd, (struct sockaddr *)&addr, &addrlen);

		if (new_client_fd == -1) {
			perror("accept");
			quit(-1);
		}

		int ret = fork();
		if (ret < 0) {
			perror("fork");
			quit(-1);
		}

		if (ret == 0) {
			client_fd = new_client_fd;
			handle_client(client_fd);
			exit(0);
		}
		close_socket(new_client_fd);
	}

	cleanup();
	return 0;
}
