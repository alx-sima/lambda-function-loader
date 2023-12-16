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

#define CUSTOM_ERR_CODE -1

static int server_fd;
static int client_fd;
static struct lib *global_lib;

void get_config(int argc, char **argv)
{
	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], argv[i]) == 0) {
			if (strcmp(argv[i], "max_connections") == 0) {
				settings.max_connections = atoi(argv[i + 1]);
				return;
			}
			if (strcmp(argv[i], "socket_type") == 0) {
				if (strcmp(argv[i + 1], "unix") == 0) {
					settings.socket_type = UNIX;
					return;
				} else if (strcmp(argv[i + 1], "inet") == 0) {
					settings.socket_type = INET;
					return;
				} else {
					printf("Invalid socket type: %s\n", argv[i + 1]);
					exit(CUSTOM_ERR_CODE);
				}
			}
		}
	}

	char *env = getenv("max_connections");
	if (env) {
		settings.max_connections = atoi(env);
		return;
	}

	env = getenv("socket_type");
	if (env) {
		if (strcmp(env, "unix") == 0) {
			settings.socket_type = UNIX;
			return;
		} else if (strcmp(env, "inet") == 0) {
			settings.socket_type = INET;
			return;
		} else {
			printf("Invalid socket type: %s\n", env);
			exit(CUSTOM_ERR_CODE);
		}
	}
}

static void cleanup()
{
	puts("\nClosing server...");
	while (waitpid(CUSTOM_ERR_CODE, NULL, 0) > 0)
		;
	close_socket(server_fd);
	close_socket(client_fd);
	int ret = remove(SOCKET_NAME);
	if (ret == CUSTOM_ERR_CODE) {
		perror("remove");
		exit(CUSTOM_ERR_CODE);
	}

	exit(0);
}

/**
 * Build error message and write it to outputfile.
 */
void print_error(char *errmsg)
{
	FILE *fp = fopen(global_lib->outputfile, "wt");
	char error_buffer[BUFSIZ] = {0};
	sprintf(error_buffer, "Error: %s ", global_lib->libname);
	if (strlen(global_lib->funcname) > 0) {
		strcat(error_buffer, global_lib->funcname);
		strcat(error_buffer, " ");

		if (strlen(global_lib->filename) > 0) {
			strcat(error_buffer, global_lib->filename);
			strcat(error_buffer, " ");
		}
	}

	if (errmsg) {
		fprintf(fp, "%scould not be executed (%s).\n", error_buffer, errmsg);
	} else {
		fprintf(fp, "%scould not be executed.\n", error_buffer);
	}
	fclose(fp);
	send(client_fd, global_lib->outputfile, strlen(global_lib->outputfile), 0);
	close_socket(client_fd);
}

static void handle_sigint()
{
	cleanup();
}

static void handle_segfault()
{
	print_error("segfault");
	exit(CUSTOM_ERR_CODE);
}

static void handle_error_exit(int status, void *arg)
{
	(void)arg;
	if (status != 0 && status != CUSTOM_ERR_CODE) {
		print_error("exit code");
	}
}

static void quit(int status)
{
	cleanup();
	exit(status);
}

static int lib_prehooks(struct lib *lib)
{
	/* Create outputfile name. */
	const size_t len = strlen(OUTPUT_TEMPLATE) + 1;
	lib->outputfile = malloc(len);
	if (!lib->outputfile) {
		perror("malloc");
		return CUSTOM_ERR_CODE;
	}
	strncpy(lib->outputfile, OUTPUT_TEMPLATE, len);

	/* Create outputfile. */
	int outfile = mkstemp(lib->outputfile);
	if (outfile == CUSTOM_ERR_CODE) {
		perror("mkstemp");
		return CUSTOM_ERR_CODE;
	}

	return 0;
}

static int lib_load(struct lib *lib)
{
	lib->handle = dlopen(lib->libname, RTLD_LAZY);

	if (!lib->handle) {
		perror("dlopen");
		print_error(NULL);
		return CUSTOM_ERR_CODE;
	}

	(void)dlerror();
	void *addr = dlsym(lib->handle, lib->funcname);

	if (!addr) {
		print_error(NULL);
		return CUSTOM_ERR_CODE;
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

		/* Handle function segfault. */
		signal(SIGSEGV, handle_segfault);

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
	(void)lib;
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
		return CUSTOM_ERR_CODE;

	return ret;
}

void handle_client()
{
	char buf[BUFSIZE] = {0};

	if (recv_socket(client_fd, buf, BUFSIZE) < 0) {
		perror("recv err");
		quit(CUSTOM_ERR_CODE);
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
	global_lib = &lib;

	if (lib_run(&lib) < 0) {
		perror("run err");
		quit(CUSTOM_ERR_CODE);
	}

	if (send_socket(client_fd, lib.outputfile, strlen(lib.outputfile)) < 0) {
		perror("send err");
		quit(CUSTOM_ERR_CODE);
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
	if (ret == CUSTOM_ERR_CODE) {
		perror("bind");
		quit(CUSTOM_ERR_CODE);
	}

	if (listen(server_fd, settings.max_connections) < 0) {
		perror("listen");
		quit(CUSTOM_ERR_CODE);
	}
}

int main(int argc, char **argv)
{
	get_config(argc, argv);

	struct sockaddr_un addr;
	socklen_t addrlen = sizeof(addr);
	init_server(&addr, addrlen);

	while (1) {
		int new_client_fd =
			accept(server_fd, (struct sockaddr *)&addr, &addrlen);

		if (new_client_fd == CUSTOM_ERR_CODE) {
			perror("accept");
			quit(CUSTOM_ERR_CODE);
		}

		int ret = fork();
		if (ret < 0) {
			perror("fork");
			quit(CUSTOM_ERR_CODE);
		}

		if (ret == 0) {
			/* Handle exiting with errors. */
			ret = on_exit(handle_error_exit, NULL);
			if (ret != 0) {
				perror("on_exit");
				quit(CUSTOM_ERR_CODE);
			}

			client_fd = new_client_fd;
			handle_client();
			exit(0);
		}
		close_socket(new_client_fd);
	}

	cleanup();
	return 0;
}
