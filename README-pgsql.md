# unofficial output module to PostgreSQL database

This is unofficial output module 
for [dnstap\_receiver](https://github.com/dmachard/dnstap-receiver)
to write out to [PostgreSQL](https://www.postgresql.org/docs/13/index.html) database,
using [asyncpg](https://magicstack.github.io/asyncpg/current/index.html).

## Installation

- git clone, checkout `pgsql` branch, and setup.
```shell
$ git clone https://github.com/motok/dnstap-receiver.git
$ cd dnstap-receiver
$ git checkout pgsql
$ python3 setup.j2 develop
```

## Output Handler
### pgsql

This output enables to forward dnstap messages to PostgreSQL database.
Add configuration below to activate this output.
See dnstap\_receiver/dnstap.conf for default configurations.

```yaml
output:
  pgsql:
    enable:       true
    dsn:          postgres://postgres@localhost:5432/postgres
    passfile:     ~/.pgpass
    userfuncfile: null
```

- `enable` enables/disables this (pgsql) output module.
- `dsn` represents the PostgreSQL server to be connected.
  Please don't explicitly write password in the dsn,
  instead please use passfile parameter below.
- `passfile` is a file name, as equivalent to PGPASSFILE.
- `userfuncfile` is a file name that contains two user defined functions.
  If null (default), it uses default functions in `dnstap\_receiver/outputs/output\_pgsql\_userfunc.py`.
  You can write your own and designate the file name here, then you can use them.

## Caveats

- output\_pgsql module is under Alpha level, though it is working anyway in my environment.
- known bug: You cannot stop by Ctl-C but have to `kill -KILL` to the process.
- comments/questions/suggestions are all very welcomed.
