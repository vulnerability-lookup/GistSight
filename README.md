# GistSight

A client for gathering vulnerability-related information from GitHub Gists.
The collected data is then sent to the
[Vulnerability-Lookup](https://github.com/cve-search/vulnerability-lookup) API as sightings.


## Installation

[pipx](https://github.com/pypa/pipx) is an easy way to install and run Python applications in isolated environments.
It's easy to [install](https://github.com/pypa/pipx?tab=readme-ov-file#on-linux).

```bash
$ pipx install GistSight
$ export GISTSIGHT_CONFIG=~/.gistsight/conf.py
```

### Collecting new Gists


```bash
$ GistSight
Waiting 10 seconds before next run...
No vulnerabilities found.
Waiting 10 seconds before next run...
No vulnerabilities found.
Waiting 10 seconds before next run...
Gist: https://gist.github.com/voidvxvt/719c34da30a644b822765729be648985
Created At: 2025-01-06T18:43:12+00:00
Vulnerabilities: CVE-2021-26828
--------------------------------------------------
Pushing sighting to Vulnerability-Lookup…
{'type': 'seen', 'source': 'https://gist.github.com/voidvxvt/719c34da30a644b822765729be648985', 'vulnerability': 'CVE-2021-26828', 'creation_timestamp': datetime.datetime(2025, 1, 6, 18, 43, 12, tzinfo=datetime.timezone.utc)}
Waiting 10 seconds before next run...
```



## License

[GistSight](https://github.com/CIRCL/GistSight) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2025 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2025 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~
