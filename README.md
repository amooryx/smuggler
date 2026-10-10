<div align="center">
  <img src="./banner.svg" alt="smuggler" width="800">
</div>

# smuggler

Bounded HTTP parser diagnostics for explicitly authorized testing only.

```bash
python smuggler.py --help
```

## Safety and interpretation

Request-smuggling diagnostics use ambiguous HTTP framing and can disrupt a service,
desynchronize connections, or affect other users. Run only on a system you own or
have explicit permission to test, within the exact approved host and port scope.
Do not run against production or shared services without an approved test window.
The required `--scope` value is an operator-supplied scope check; it does not
establish authorization by itself.

Each technique sends one connection containing two pipelined requests. The
connection timeout defaults to 2 seconds and is capped at 5 seconds per
technique; response data is capped at 8 KiB per technique. Raw socket requests
do not follow redirects. A DNS lookup may take longer than the socket timeout,
depending on the operating system and resolver.

Example using a local service only:

```bash
python smuggler.py 127.0.0.1 --port 8080 --scope 127.0.0.1:8080 --no-ssl
```

`400`/`405` statuses or the probe's `GPOST` token in a response are observations only.
They do not confirm a request-smuggling vulnerability; verify any suspected
behavior through a separately authorized, controlled assessment.

## Dependencies

Python 3.10 or newer; the tool uses only the Python standard library.

## Tests

Run the offline tests; their protocol fixtures bind only to loopback:

```bash
python -m unittest discover -s tests -v
```

## Author

**Omar Khalid**
