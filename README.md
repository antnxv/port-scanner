# port-scanner
Anthony Nosaryev

ECE-303 Project 1

2 Mar 2025

## Dependencies

- C environment.
- GNU Make, `gcc` to compile project.
- The following platform-dependent C libraries:
  - `arpa/inet.h`
  - `netinet/in.h`
  - `sys/socket.h`
  - `netdb.h`
  - `sys/epoll.h` (Linux only)
  - `sys/types.h`

## Files

- `Makefile`: Builds portscan executable using the below files.
- `portscan.c/h`: Provides main() containing high-level parsing and scanning logic.
- `parse.c/h`: Command-line and input file input parsing.
- `scan.c/h`: Port batching, connection forming/handling and output.
- `service.h`: Maps port numbers to well known services.

## Building and Usage

- Running `make` will compile the portscan binary executable which can then be used in the fashion described below. `make clean` is also specified to remove the executable and all object files generated during building.

```
Usage: portscan OPTIONS

--ports (-p) START[:END]
 Port (range) to scan. Default 1-1024, valid 1-65535.
 Do not supply an input file.

--ip (-i) IP_ADDR
 IP Address to scan. Default localhost.
 Do not supply an input file.

--input (--list, -l) FILENAME
 List of IP Addresses and ports to iteratively scan.
 Entries must be of the format IP_ADDR\tPORT_START\tPORT_END.
 Do not supply IP or port(s) to command line.
 
--output (-o) FILENAME
 Optional output file.

--help (-h)
 Print this information and discard other arguments.
```

## Features/Notes

Operation:
- When specifying a destination IP Address, 'localhost' is understood to mean '127.0.0.1'.
- Input files entries of the format specified above can be separated by an arbitrary number of newlines.
- Connections are formed concurrently in batches and without blocking to avoid excessive buildup of timeout delays.
  - Timeout is fixed to 750ms with the `TIMEOUT` preprocessor macro.
  - The maximum number of open file descriptors/sockets will vary from system to system. This implementation limits the maximum number of sockets at any given moment to 256 with the `MAX_EVENTS` preprocessor macro to avoid error.
  - Decreasing `TIMEOUT` or increasing `MAX_EVENTS` will hasten the port-scanner at the risk of lower accuracy and potential error respectively.
  - This methodology is discussed under `EINPROGRESS` on the [connect(2) Linux manual page](https://www.man7.org/linux/man-pages/man2/connect.2.html).

Output:
- When an output file is specified, errors and program progress information are reported not to the output file but to stderr.
- Open ports are printed in either batches of consecutive ports (e.g. if ports 12000 through 12005 were open, the output would contain Ports 12000-12005) or individually if consecutive ports are closed or if the typical protocol associated with the port is known.
  - Known protocols taken from [RFC 1700](https://www.rfc-editor.org/rfc/rfc1700).
  - Note that RFC 1700 is obsolete and out of date with port number service registrations as maintained by the [Internet Assigned Numbers Authority (IANA)](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml). RFC 1700 was referenced for convenience.
