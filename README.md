# Lambda Function Loader

Authors: Sima Alexandru (322 CA) & Stan Andrei (322 CA)

A small program showcasing basic usage of C sockets (Unix / internet).

## Application Development

### `ipc.c`

The source file contains functions regarding creation, closing of sockets,
sending and receiving data.

### `server.c`

This is where the server implementation resides.

In `main()` the flow is as follows:

- Initialize the server through `init_server()`.
  - This function initializes 3 handlers for kill signals: `SIGINT`, `SIGHUP`,
  and `SIGTERM`. 
  - Then the socket is initialized, bound and listening is started.
- An inifinite loop is started that waits for connections and for each client
that connects, it spawns a new process to handle it.

The function `handle_client()` handled the clients that connect. The command is
read from the socket, parsed and the lib is created with error checking.

Finally, the command output is sent to the client.

### Lib functions

These are a collection of function for instantiating the library and calling
the respective function. It uses `dlopen()` to dynamically link the library.

## Functionalities

### Library calling

The clients are able to load libraries on the server and execute
their functions.

### Error checking

- Only specific libraries that the server admin authorized can be used.
- In case the function executed faults, signals are trapped and an error message
is sent back to the client.
- In case the function executed exits with a non-zero error code, the exit call 
is caught and an error message is sent back to the client.

### Configuration

The server supports configuration for different parameters via command line
arguments or environment variables:

- `max_connections`: 5
- `socket_type`: UNIX
- `max_runtime_seconds`: 5

Environment variabled override command line parameters.

## Bonuses

- Clumsy Program detailed in error checking section.
- Sleepy program detailed in error checking section.

