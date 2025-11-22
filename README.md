# IPFire pmacct Web Interface

A modern, real-time NetFlow/sFlow traffic accounting interface for IPFire.

This CGI provides a live top-talker view using pmacct's memory plugin with full integration into the native IPFire web user interface.

## Features

- Real-time traffic overview (top talkers)
- Human-readable byte counters (B → KB → MB → GB → TB)
- Full IPFire zone coloring (GREEN, BLUE, ORANGE, RED, VPN, WireGuard, OpenVPN)
- Clickable IP addresses open `ipinfo.cgi` (Whois, GeoIP, blocklist check) in a new tab
- Column-based search including "All columns" mode
- Client-side sorting (works correctly even with formatted byte values)
- Client-side pagination (10 / 20 / 50 / 100 / 250 / 500 / All rows per page)
- Configurable live refresh (off / 2 s / 5 s / 10 s)
- 100 % original IPFire look & feel – no Bootstrap, no external libraries

## Requirements

- IPFire 2.27+ (Core 170 or newer recommended)
- pmacct installed from Pakfire with basic configuration with the memory plugin.


## Installation

```bash
sudo cp pmacct.cgi /srv/web/ipfire/cgi-bin/pmacct.cgi
sudo chmod 755 /srv/web/ipfire/cgi-bin/pmacct.cgi
sudo chown nobody:nobody /srv/web/ipfire/cgi-bin/pmacct.cgi
```

Open in browser:
`https://your-ipfire:444/cgi-bin/pmacct.cgi`

## Configuration

No additional configuration is required. The script automatically detects:

All network zones (GREEN, BLUE, ORANGE)
RED interface and aliases
VPN, OpenVPN and WireGuard subnets

## Contributing

Contributions are very welcome!
Feel free to open issues or submit pull requests.
Ideas for future enhancements:

- Official menu entry under Status → Realtime Monitoring
- Preset filter buttons (HTTPS, DNS, SSH, LAN→Internet, etc.)
- CSV export
- RRD-based graphs (traffic over time)

## License

GNU General Public License v3.0 (same as IPFire)

Made with ❤️ for the IPFire community
