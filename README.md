# Huawei-N5368X-crawler

This is fork repository of original [Huawei Outdoor 5G CPE N5368X crawler project](https://github.com/samikentta/Huawei-N5368X-crawler) made by @samikentta.

This script is able to login to Huawei Outdoor 5G CPE N5368X and fetch some example data. Script also includes the possibility to write data to Influx database e.g. for monitoring purposes. This version currently uses InfluxDB 2.0.4 version.

NOTE! This script is intended to be used as an example. Script comes without any warranty & support.

Script has dependencies to quite a few Python3 packages which are described in [requirements.txt](requirements.txt).

Install python dependies:

```
    pip3 install -r requirements.txt
```

## Configurations
To configurations of Huawei unit and InfluxDB are done in [settings.yml](settings.yml) or you can overdrive all or some of configurations by giving overdrive values in `settings-overdrive.yml` file.

Example:
You have following values in [settings.yml](settings.yml)

```
ROUTER: "router ip address" # Router IP address
USER: "your_username"       # Router username
PASSWORD: "your_password"   # Router password
LOG_LEVEL: "INFO"           # Logging level
```

and you will give
`settings-overdrive.yml`
```
ROUTER: "xxx.yyy.zzz.a"
USER: "my_name"
PASSWORD: "passwd"
LOG_LEVEL: "DEBUG"
```
So `huawei-n5368x-crawler.py` will use overdrived values values in script
