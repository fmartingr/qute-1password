# Qute-1Password

Qutebrowser userscript to fill 1password credentials

![Oh, stop it! you...](.readme/stopityou.png)

## Dependencies

- [The 1Password CLI](https://support.1password.com/command-line-getting-started/)
  Ensure you have it installed and set up. Follow the official documentation.
> ℹ️ **Note**: Only the 1Password CLI v2 is supported.
- [rofi](https://github.com/davatorium/rofi) to ask for password and list items

## How it works

First we will ask for the master password using Rofi to get all login items.

Then it'll get the hostname from the current URL and filter results from all the login items stored in the 1password account logged in.

A new Rofi prompt will show up to select one item from the filtered list (items that only match for the current site based on the hostname)

Once an item is selected, we will retrieve it and submit it in the browser by injecting they characters as if the keyboard were writting them, using a `<tab>` to switch fields and a `<cr>` to submit the form. This is done using the [`fake-key`](https://qutebrowser.org/doc/help/commands.html#fake-key) qutebrowser command.

## Usage

Right now it defaults to the `my` account, will be configurable in the future.

Commands:
- `fill_credentials`: Will send the username and password (using a `<tab>` keystroke in between)
- `fill_username`: Will send the username
- `fill_password`: Will send the password
- `fill_totp`: Will send the TOTP

Flags:
- `--auto-submit` Will send a carriage return once the last character is sent, hopefully submitting the form.
- `--cache-session` Caches the session for 30 minutes to prevent asking for the password again in that interval.
- `--allow-insecure-sites` Allow filling in insecure (non-https) sites
- `--biometric` Use biometric or PAM authentication instead of asking for the master password

Using the biometric flag requires installing the 1Password Desktop app and enabling "Biometric unlock" in it's Developer options.

```
$ python qute_1pass.py --help
usage: qute_1pass.py [-h] [--auto-submit] [--cache-session] [--allow-insecure-sites] [--cache] [--biometric] command

positional arguments:
  command               fill_credentials, fill_totp, fill_username, fill_password

options:
  -h, --help            show this help message and exit
  --auto-submit         Auto submit after filling
  --cache-session       Cache 1password session for 30 minutes
  --allow-insecure-sites
                        Allow filling credentials on insecure sites
  --cache               store and use cached information
  --biometric           Use biometric unlock - don't ask for password
```

Call your script from qutebrowser using

```
:spawn --userscript path/to/qute_1pass.py fill_credentials
```

## Contributing

In this project we use [Poetry](https://python-poetry.org/) to manage the python dependencies and virtual environments. Make sure you have it installed before continuing.

Use this command to create the virtualenv, install dev-dependencies and
install the pre-commit hook.

``` bash
make setup
```

After you make your desired changes, open a merge request or send me a patch via email and I will review it as soon as I can.
