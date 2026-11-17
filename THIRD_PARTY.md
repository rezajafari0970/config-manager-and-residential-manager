# Third-party components

Runtime downloads are fetched from their publishers and checked against `deploy/dependencies.json`. No live configurations, account keys, country databases or server backups are distributed in this repository.

- [Xray-core](https://github.com/XTLS/Xray-core): MPL-2.0; upstream release archives may include geoip/geosite assets and their own notices. Versions are pinned per driver.
- [sing-box](https://github.com/SagerNet/sing-box): GPL-3.0; downloaded from upstream release assets, not relicensed by this project.
- [Go](https://go.dev/): BSD-style license, used temporarily to build the application.
- [aioquic](https://github.com/aiortc/aioquic): BSD-3-Clause; Python dependencies retain their respective licenses.
- Go dependencies are recorded in `go.mod` and `go.sum`; their upstream licenses remain applicable.
- [Vazirmatn](https://github.com/rastikerdar/vazirmatn): SIL Open Font License 1.1. See `internal/panel/web/OFL.txt`.
- [DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite): CC BY 4.0. Credit: IP Geolocation by DB-IP.
- [IPLocate IP address databases](https://github.com/iplocate/ip-address-databases): CC BY-SA 4.0. Credit: IPLocate.io. Locally transformed country tables retain the source attribution and share-alike terms.
- [GeoJS](https://www.geojs.io/): external country information service; availability and service terms are independent of this project.

Distribution through GitHub does not change third-party licenses. This repository does not grant a new license for third-party components.
