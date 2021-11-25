# DumpRadius

A radius server that has not user database but checks against username with a hmac hash.

A.K.A ` password = ts + truncate(hmac(key+ts+username)) `

```
dumb_radius 0.1.0

USAGE:
    dumb_radius [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -b, --bind <bind>        radius bind address [env: DUMB_RADIUS_BIND=]  [default: 0.0.0.0]
    -p, --port <port>        radius port [env: DUMB_RADIUS_PORT=]  [default: 1812]
    -k, --key <pwd_key>      password key [env: DUMB_RADIUS_KEY=]  [default: whosyourdaddy]
    -s, --secret <secret>    radius secret [env: DUMB_RADIUS_SECRET=]  [default: 12345678]

SUBCOMMANDS:
    genpwd    generate passwords for testing
    help      Prints this message or the help of the given subcommand(s)
```