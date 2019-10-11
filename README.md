# Qute-1Password

Qutebrowser userscript to fill 1password credentials

![Oh, stop it! you...](.readme/stopityou.png)

## Dependencies

- [The 1Password CLI](https://support.1password.com/command-line-getting-started/)
  Ensure you have it installed and set up. Follow the official documentation.
- [rofi](https://github.com/davatorium/rofi) to ask for password and list items

## Usage

Right now it defaults to the `my` account, will be configurable in the future.

```
./qute_1pass.py --help
usage: qute_1pass.py [-h] [--auto-submit] [--cache-session] command

positional arguments:
  command          fill_credentials, fill_totp

optional arguments:
  -h, --help       show this help message and exit
  --auto-submit    Auto submit after filling
  --cache-session  Cache 1password session for 30 minutes
```

Call your script from qutebrowser using

```
:spawn --userscript path/to/qute_1pass.py fill_credentials
```

## Contributing

In this project we use Poetry_ to manage the python dependencies and virtual environments. Make sure you have it installed before continuing.

Use this command to create the virtualenv, install dev-dependencies and
install the pre-commit hook.

``` bash
make setup
```

After you make your desired changes, open a merge request and I will review it as soon
as I can.
