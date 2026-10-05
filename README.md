# api-fetcher-termux

# API Fetcher for Termux

HTTP/API client using only the Python standard library.

Requires Python 3.8 or newer. No pip dependencies are needed.

## Install in regular Termux

```bash
pkg install git python
git clone https://github.com/karmabuild49/api-fetcher-termux.git
cd api-fetcher-termux
python get_api.py --help
```

## Fetch an endpoint

```bash
python get_api.py https://api.github.com --status
```

## Save a response

```bash
python get_api.py https://api.github.com -o output/github.json
```

## Send JSON

```bash
python get_api.py https://httpbin.org/post \
  --data '{"hello":"world"}'
```

Data selects POST unless an explicit method is supplied.

```bash
python get_api.py https://httpbin.org/put \
  -X PUT --data '{"hello":"world"}'
```

Request bodies default to Content-Type: application/json.
Override this header for other formats.

## Read a request body from a file

```bash
python get_api.py https://httpbin.org/post \
  --data-file request.json
```

## Headers and authentication

```bash
python get_api.py https://api.github.com \
  -H "Accept: application/json"
```

```bash
export API_TOKEN='your-token'
python get_api.py https://api.github.com/user \
  --token-env API_TOKEN
```

Never commit tokens or credentials.

## Other options

```bash
python get_api.py https://api.github.com \
  --timeout 10 --response-headers

python get_api.py https://api.github.com --raw

python get_api.py https://api.github.com --no-redirect

python get_api.py --version
```

JSON responses are formatted unless --raw is supplied.
Non-JSON text responses are supported.

Output files contain decoded UTF-8 text; they are not
byte-preserving binary downloads.

Status and response headers are printed to stderr.

With --output, HTTP error bodies are also saved.
The command still exits with code 1.

Authorization, Cookie and Proxy-Authorization headers are
removed when redirecting to a different origin.
Custom secret headers are not identified automatically;
use --no-redirect when sending them.

TLS certificate verification remains enabled.

## Exit codes

- 0: success
- 1: HTTP, network or output error, or a blocked redirect
- 2: invalid arguments or missing token
- 130: interrupted request

## Tests

Run from the project directory:

```bash
python -m unittest discover -s ./tests -v
python -m py_compile get_api.py
```

The seven tests use local HTTP servers.
No internet connection or third-party packages are needed.

GitHub Actions runs the tests on Python 3.8 and 3.13.

## License

No license has been selected.
