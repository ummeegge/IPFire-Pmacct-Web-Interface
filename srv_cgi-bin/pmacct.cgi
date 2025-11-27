#!/usr/bin/perl
#===============================================================================
# pmacct.cgi – Live NetFlow/sFlow Traffic Accounting for IPFire
#
# Features:
# - Human-readable byte counters
# - Full IPFire zone coloring (including WireGuard/OpenVPN etc.)
# - Clickable IPs → ipinfo.cgi
# - Live refresh, client-side search/sorting/pagination
# - Natural IPv4 sorting (2.x comes before 95.x – finally!)
# - Search "All columns" without false positives across borders
# - CSV export
# - Full XSS protection including single quotes
# - Maximum 1000 flows, cached network list, bulletproof error handling
# - Configurable data sources from pmacct.conf (memory plugins with pipe parsing)
# - Support for multiple memory plugins via dropdown selection
# - Automatic fallback to default pipe (/tmp/collect.pipe) if no valid config
# - "Show provider names & flags" checkbox – replaces IPs with AS names
#       (e.g. "Google LLC", "Hetzner Online GmbH", "Cloudflare, Inc.")
#       + country flags, powered by IPFire's native libloc database
#
# Author: ummeegge
# Version: 0.9
# License: GPL-3.0
#===============================================================================
use strict;
use warnings;
no warnings 'once';
use CGI qw(:standard);
use CGI::Carp qw(fatalsToBrowser warningsToBrowser);
use JSON::PP qw(encode_json);
use IPC::Open3;  # For secure command execution
use List::Util qw(all);  # For IP validation

require '/var/ipfire/general-functions.pl';
require '/var/ipfire/header.pl';
require '/var/ipfire/lang.pl';
require '/var/ipfire/ids-functions.pl';
require '/var/ipfire/network-functions.pl';
require "${General::swroot}/location-functions.pl";

# ---------------------------------------------------------------------------
# Server-side cache for location lookups (IP → display string + flag)
# ---------------------------------------------------------------------------
our %LOCATION_CACHE;

# ---------------------------------------------------------------------------
# Logging variables and subroutines for UI messages
# Collects errors, warnings, and infos for display in IPFire-style boxes.
# ---------------------------------------------------------------------------
my $errormessage = '';
my $infomessage  = '';
my $warnmessage  = '';

sub log_error {
	my $msg = shift;
	$errormessage .= "$msg\n";
	warn $msg;  # Also log to server error log if needed
}

sub log_info {
	my $msg = shift;
	$infomessage .= "$msg\n";
}

sub log_warning {
	my $msg = shift;
	$warnmessage .= "$msg\n";
	warn $msg;
}

sub show_messages {
	if ($errormessage) {
		&Header::openbox('100%', 'left', $Lang::tr{'error messages'});
		print "<div class='base'>" . html_escape($errormessage) . "</div>";
		&Header::closebox();
	}
	if ($warnmessage) {
		&Header::openbox('100%', 'left', $Lang::tr{'warning messages'});
		print "<div class='base' style='background-color:yellow;'>" . html_escape($warnmessage) . "</div>";
		&Header::closebox();
	}
	if ($infomessage) {
		&Header::openbox('100%', 'left', $Lang::tr{'info messages'});
		print "<div class='base'>" . html_escape($infomessage) . "</div>";
		&Header::closebox();
	}
}

# ---------------------------------------------------------------------------
# Build zone-to-color mapping – cached sorted list for performance
# This section reads IPFire settings and builds a hash of networks with associated colors.
# It includes local zones, RED interface, aliases, and VPN subnets for coloring IPs in the UI.
# ---------------------------------------------------------------------------
my %mainsettings = ();
&General::readhash("/var/ipfire/ethernet/settings", \%mainsettings);

my %networks = (
	"127.0.0.0/8" => ${Header::colourfw},
	"224.0.0.0/4" => "#A0A0A0", # Multicast
);

# Local zones (GREEN, BLUE, ORANGE)
if ($mainsettings{'GREEN_NETADDRESS'}) {
	$networks{"$mainsettings{'GREEN_NETADDRESS'}/$mainsettings{'GREEN_NETMASK'}"} = ${Header::colourgreen};
}

if ($mainsettings{'BLUE_NETADDRESS'}) {
	$networks{"$mainsettings{'BLUE_NETADDRESS'}/$mainsettings{'BLUE_NETMASK'}"} = ${Header::colourblue};
}

if ($mainsettings{'ORANGE_NETADDRESS'}) {
	$networks{"$mainsettings{'ORANGE_NETADDRESS'}/$mainsettings{'ORANGE_NETMASK'}"} = ${Header::colourorange};
}

# RED interface + aliases
my $red = &IDS::get_red_address();
$networks{"${red}/32"} = ${Header::colourfw} if $red;
foreach my $alias (&IDS::get_aliases()) {
	$networks{"${alias}/32"} = ${Header::colourfw} if $alias;
}

# VPN / OpenVPN / WireGuard subnets
if (-e "/var/ipfire/vpn/config") {
	if (open(my $fh, "<", "/var/ipfire/vpn/config")) {
		while (<$fh>) {
			my @vpn = split(/,/, $_);
			my @subnets = split(/\|/, $vpn[12] // '');
			$networks{$_} = ${Header::colourvpn} for grep {$_} @subnets;
		}
		close($fh);
	}
}

if (-e "/var/ipfire/ovpn/settings") {
	my %ovpn = ();
	&General::readhash("/var/ipfire/ovpn/settings", \%ovpn);
	$networks{$ovpn{'DOVPN_SUBNET'}} = ${Header::colourovpn} if $ovpn{'DOVPN_SUBNET'};
}

if (-e "/var/ipfire/wireguard/settings") {
	my %wg = ();
	&General::readhash("/var/ipfire/wireguard/settings", \%wg);
	$networks{$wg{'CLIENT_POOL'}} = ${Header::colourwg} if $wg{'CLIENT_POOL'};
}

# Cached sorted network list – longest prefix first (most specific match wins)
my @sorted_networks = sort { &Network::get_prefix($b) <=> &Network::get_prefix($a) } keys %networks;

# ---------------------------------------------------------------------------
# Subroutine to return background color for a given IP
# Uses cached network list for fast lookup; defaults to red for internet IPs.
# ---------------------------------------------------------------------------
sub ipcolour {
	my $ip = shift // return ${Header::colourred};
	# Strict IPv4 validation with octet range check
	return ${Header::colourred} unless $ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
		&& all { $_ >= 0 && $_ <= 255 } split(/\./, $ip);
	foreach my $net (@sorted_networks) {
		next unless &Network::check_subnet($net);
		return $networks{$net} if &Network::ip_address_in_network($ip, $net);
	}
	return ${Header::colourred}; # Everything else = Internet (RED)
}

# ---------------------------------------------------------------------------
# Subroutine for full HTML entity escaping
# Protects against XSS by escaping special characters, including single quotes.
# ---------------------------------------------------------------------------
sub html_escape {
	my $text = shift // '';
	$text =~ s/&/&amp;/g;
	$text =~ s/</&lt;/g;
	$text =~ s/>/&gt;/g;
	$text =~ s/"/&quot;/g;
	$text =~ s/'/&#39;/g;
	return $text;
}

# ---------------------------------------------------------------------------
# Subroutine to parse pmacct.conf for memory plugins and pipes
# Extracts all memory plugins from 'plugins:' line (handles multiple in one line).
# Matches corresponding imt_path for each; skips if no path; fallback to default pipe.
# Warns on issues but does not skip valid pipes for robustness.
# ---------------------------------------------------------------------------
sub get_pmacct_memory_pipes {
	my $conf_file = '/etc/pmacct/pmacct.conf';
	my $default_pipe = '/tmp/collect.pipe';
	my %pipes = ();
	my %found_plugins = ();
	unless (-r $conf_file) {
		log_warning("pmacct.conf not readable: $conf_file - trying default pipe");
		return { 'default' => $default_pipe } if -e $default_pipe;
		return {}; # No fallback if default does not exist → Error
	}
	open(my $fh, '<', $conf_file) or do {
		log_warning("Failed to open pmacct.conf: $! - trying default pipe");
		return { 'default' => $default_pipe } if -e $default_pipe;
		return {};
	};
	while (<$fh>) {
		next if /^\s*[!#]/ || !/\S/; # Skip comments/empty
		if (/^\s*plugins:\s*/i) {
			while (/memory\s*\[\s*plugin(\d+)\s*\]/ig) {
			$found_plugins{"plugin$1"} = 1;
			}
			next;
		}
		if (/^\s*imt_path\s*\[\s*plugin(\d+)\s*\]\s*:\s*(.+?)\s*$/i) {
			my $plugin_num = $1;
			my $pipe = $2;
			$pipe =~ s/\s+//g;  # Trim whitespace for clean path
			my $plugin = "plugin$plugin_num";
			if (exists $found_plugins{$plugin}) {
				$pipes{$plugin} = $pipe;
				delete $found_plugins{$plugin};
			}
		}
	}
	close($fh);
	# Skip pending plugins without pipe
	foreach my $pending (keys %found_plugins) {
		log_warning("Skipping $pending: No imt_path defined");
	}
	# Global fallback if nothing valid
	unless (keys %pipes) {
		log_warning("No valid memory plugins with pipes found - using default pipe if available");
		return { 'default' => $default_pipe } if -e $default_pipe;
		return {}; # Skip everything → Error in WUI
	}
	# Checks: Daemon and pipe existence/readability – warn and skip invalid
	my @ps = `ps aux | grep '[p]macctd' 2>/dev/null`;
	unless (@ps) {
		log_warning("pmacctd daemon not running");
	}
	foreach my $plugin (keys %pipes) {
		my $pipe = $pipes{$plugin};
		log_info("Checking pipe/socket for $plugin: $pipe");  # Debug log
		if (-e $pipe) {
			unless (-r $pipe && (-p $pipe || -S $pipe)) {  # Support both FIFO (p) and socket (S)
			log_warning("Pipe/socket for $plugin exists but not readable or invalid type: $pipe");
			delete $pipes{$plugin};
		}
	} else {
		log_warning("Pipe/socket for $plugin does not exist: $pipe – skipping");
		delete $pipes{$plugin};
		}
	}
	# Final check: No valid pipes left
	unless (keys %pipes) {
		log_error("No valid pipes/sockets found after checks");
		return {};
	}
	return \%pipes;
}

# ---------------------------------------------------------------------------
# CGI handling section
# Processes GET requests for data (JSON) or renders the HTML page.
# ---------------------------------------------------------------------------
my $q = CGI->new;
if ($q->param('action') && $q->param('action') eq 'get_data') {
	print $q->header(-type => 'application/json', -charset => 'utf-8');
	my $data = get_pmacct_data();
	print encode_json($data);
	exit 0;
}

# ---------------------------------------------------------------------------
# Location Lookup Handler – pure libloc version (no DNS/PTR anymore)
# ---------------------------------------------------------------------------
if ($q->param('action') && $q->param('action') eq 'location_lookup') {
	my $ip = $q->param('ip') // '';
	print $q->header(-type => 'application/json', -charset => 'utf-8');

	# Accept both IPv4 and IPv6
	if (&General::validip($ip) || &General::validip6($ip)) {

		# Return cached result if we already resolved this IP
		if (exists $LOCATION_CACHE{$ip}) {
			print encode_json($LOCATION_CACHE{$ip});
			exit 0;
		}

		my $asn       = Location::Functions::lookup_asn($ip)       // '';
		my $as_name   = $asn ? Location::Functions::get_as_name($asn) : '';
		my $ccode     = Location::Functions::lookup_country_code($ip) // '';
		my $flag_icon = $ccode ? Location::Functions::get_flag_icon($ccode) : '';

		# Final display: AS name if available, otherwise fall back to raw IP
		my $display = $as_name ? $as_name : $ip;

		# Build result
		my $result = {
			ip        => $ip,
			display   => $display,
			flag_icon => $flag_icon,   # e.g. "/images/flags/de.png" or empty
		};

		# Cache it for this CGI run (shared across all table refreshes)
		$LOCATION_CACHE{$ip} = $result;

		print encode_json($result);
	} else {
		print encode_json({ display => $ip, flag_icon => '' });
	}
	exit 0;
}

# ---------------------------------------------------------------------------
# HTML page rendering
# Outputs the main UI with controls for refresh, pagination, search, etc.
# ---------------------------------------------------------------------------
&Header::showhttpheaders();
&Header::openpage('Pmacct Traffic Accounting', 1, '');
show_messages();  # Display any collected messages at the top
&Header::openbigbox('100%', 'left', '');
&Header::openbox('100%', 'left', 'Pmacct Live Traffic Accounting');
print qq{
	<table width="100%" cellspacing="4" cellpadding="2">
	<tr>
		<td width="20%"><strong>Data Source:</strong>
			<select id="pluginSelect" style="margin-left:10px;">
				<option value="">Loading...</option>
			</select>
		</td>
		<td width="20%"><strong>Live Update:</strong>
			<select id="refresh" style="margin-left:10px;">
				<option value="0">Off</option>
				<option value="2">2 seconds</option>
				<option value="5" selected>5 seconds</option>
				<option value="10">10 seconds</option>
			</select>
		</td>
		<td width="20%"><strong>Rows per page:</strong>
			<select id="pageSize" style="margin-left:10px;">
				<option value="10">10</option>
				<option value="20">20</option>
				<option value="50" selected>50</option>
				<option value="100">100</option>
				<option value="250">250</option>
				<option value="500">500</option>
				<option value="0">All</option>
			</select>
		</td>
		<td width="25%"><strong>Search in column:</strong>
			<select id="searchColumn" style="margin-left:10px; width:200px;">
				<option value="-1">All columns</option>
			</select>
			<input type="text" id="search" style="margin-left:10px; width:280px;" placeholder="e.g. 443, 192.168, tcp..." />
		</td>
		<td width="15%" align="right">
			<input type="button" id="manualRefresh" value="Refresh now" />
			<input type="button" id="exportCsv" value="Export CSV" style="margin-left:8px;" />
			<span id="status" style="margin-left:10px; font-weight:bold; min-width:200px; display:inline-block;">Loading...</span>
		</td>
	</tr>
	<tr>
		<td colspan="5" style="text-align:left; padding:8px 0;">
			<label style="font-weight:bold; cursor:pointer; user-select:none;">
				<input type="checkbox" id="resolveDns" style="vertical-align:middle;"> Show provider names & flags
			</label>
		</td>
	</tr>
	<tr>
		<td colspan="5" align="center">
			<div id="pagination" style="margin-top:10px; font-weight:bold;"></div>
		</td>
	</tr>
	</table>
};
&Header::closebox();
print "<div id='tablecontainer'></div>";
print "<script src='/include/jquery.js'></script>";
print qq{
<script>
	// ---------------------------------------------------------------------------
	// Global variables for UI state management
	// ---------------------------------------------------------------------------
	let refreshInterval = null;
	let currentSortCol  = null;
	let currentSortAsc  = false;
	let lastSearchTerm  = '';
	let lastSearchCol   = '-1';
	let rawData         = [];
	let allRows         = [];
	let currentPage     = 1;
	let pageSize        = 50;
	let tableMeta       = null;
	let dnsActive       = false;

	// Event Handler for DNS checkbox
	\$('#resolveDns').on('change', function() {
		dnsActive = this.checked;
		renderTable();
	});

	// ---------------------------------------------------------------------------
	// DNS Cache + Location Resolver (IPFIRE NATIVE!)
	// ---------------------------------------------------------------------------
	let dnsCache = new Map();

	async function resolveDns(ip) {
		if (!dnsActive || !isValidIPv4(ip)) return ip;

		if (dnsCache.has(ip)) {
			return dnsCache.get(ip);
		}

		try {
			const response = await fetch('/cgi-bin/pmacct.cgi?action=location_lookup&ip=' + encodeURIComponent(ip));
			if (!response.ok) {
				dnsCache.set(ip, ip);
				return ip;
			}

			const data = await response.json();
			if (data.error) {
				dnsCache.set(ip, ip);
				return ip;
			}

			// PTR > AS-Name > IP (perfekte Reihenfolge!)
			const hostname = data.display || ip;
			dnsCache.set(ip, hostname);
			return hostname;

		} catch(e) {
			dnsCache.set(ip, ip);
			return ip;
		}
	}

	// ---------------------------------------------------------------------------
	// Helper function to validate IPv4 addresses
	// ---------------------------------------------------------------------------
	function isValidIPv4(ip) {
		return /^(\\d{1,3}\\.){3}\\d{1,3}\$/.test(ip) &&
			   ip.split('.').every(o => parseInt(o,10) <= 255);
	}

	// ---------------------------------------------------------------------------
	// Function to sort the table by column
	// ---------------------------------------------------------------------------
	function sortTable(col) {
		currentSortAsc = (currentSortCol === col) ? !currentSortAsc : false;
		currentSortCol = col;
		renderTable();
	}

	// ---------------------------------------------------------------------------
	// Function to update pagination controls
	// ---------------------------------------------------------------------------
	function updatePagination(totalRows) {
		const totalPages = pageSize === 0 ? 1 : Math.ceil(totalRows / pageSize);
		currentPage = Math.min(currentPage, totalPages) || 1;
		let pag = '<strong>Page:</strong> ';
		if (pageSize === 0 || totalPages <= 1) {
			\$('#pagination').empty();
			return;
		}
		if (currentPage > 1) pag += '<a href="#" onclick="currentPage--; renderTable(); return false">&lt;&lt; Prev</a> ';
		pag += currentPage + ' / ' + totalPages;
		if (currentPage < totalPages) pag += ' <a href="#" onclick="currentPage++; renderTable(); return false">Next &gt;&gt;</a>';
		\$('#pagination').html(pag);
	}

	// ---------------------------------------------------------------------------
	// Function to render the table HTML (with post-processing for provider names)
	// ---------------------------------------------------------------------------
	function renderTable() {
		if (!tableMeta || allRows.length === 0) {
			\$('#tablecontainer').html('<p style="text-align:center;color:red;">No data available – pmacct daemon not running or pipe empty</p>');
			\$('#pagination').empty();
			return;
		}

		// === SORTING ===
		if (currentSortCol !== null) {
			allRows.sort((a, b) => {
				let A = rawData[a.idx][currentSortCol] ?? '';
				let B = rawData[b.idx][currentSortCol] ?? '';
				// IPv4 sorting
				if (currentSortCol === tableMeta.src_ip_col || currentSortCol === tableMeta.dst_ip_col) {
					const ipToNum = ip => (ip || '').split('.').map(n => parseInt(n, 10) || 0);
					const arrA = ipToNum(A);
					const arrB = ipToNum(B);
					for (let i = 0; i < 4; i++) {
						if (arrA[i] !== arrB[i]) {
							return (arrA[i] - arrB[i]) * (currentSortAsc ? 1 : -1);
						}
					}
					return 0;
				}
				// Numeric sorting
				const numA = Number(A);
				const numB = Number(B);
				if (!isNaN(numA) && !isNaN(numB)) {
					return (numA - numB) * (currentSortAsc ? 1 : -1);
				}
				// Safe string fallback
				const strA = String(A);
				const strB = String(B);
				return strA.localeCompare(strB) * (currentSortAsc ? 1 : -1);
			});
		}

		const start = pageSize === 0 ? 0 : (currentPage - 1) * pageSize;
		const end   = pageSize === 0 ? allRows.length : start + pageSize;
		const pageRows = allRows.slice(start, end);

		let html = '<table class="tbl" width="100%"><thead><tr class="tblhead">';
		tableMeta.headers.forEach((h, i) => {
			let arrow = (i === currentSortCol) ? (currentSortAsc ? ' ↑' : ' ↓') : '';
			if (i === tableMeta.bytes_col && currentSortCol === null) arrow = ' ↓';
			html += '<th style="cursor:pointer;" onclick="sortTable(' + i + ')"><b>' + h.replace(/_/g, ' ') + '</b>' + arrow + '</th>';
		});
		html += '</tr></thead><tbody>';

		pageRows.forEach(rowObj => {
			html += '<tr>';
			rowObj.cells.forEach((cell, colIdx) => {
				let content = cell || ' ';
				let bg = '';
				content = content.replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":''})[m]);

				const ipc = tableMeta.ip_colours[rowObj.idx];
				if (ipc) {
					if (colIdx === tableMeta.src_ip_col && tableMeta.src_ip_col >= 0) bg = ipc.src;
					if (colIdx === tableMeta.dst_ip_col && tableMeta.dst_ip_col >= 0) bg = ipc.dst;
				}

				if ((colIdx === tableMeta.src_ip_col || colIdx === tableMeta.dst_ip_col) && isValidIPv4(content)) {
					content = '<a href="/cgi-bin/ipinfo.cgi?ip=' + encodeURIComponent(content) +
						'" target="_blank" style="color:#FFFFFF; font-weight:bold; text-decoration:underline;" ' +
						'data-ip="' + content + '">' + content + '</a>';
				}

				html += '<td class="base dns-cell" style="background-color:' + bg + ';">' + content + '</td>';
			});
			html += '</tr>';
		});

		html += '</tbody></table>';
		\$('#tablecontainer').html(html);
		updatePagination(allRows.length);
		applySearchOnPage();

		if (dnsActive) {
			updateDnsLinks();
		}
	}

	// ---------------------------------------------------------------------------
	// Async resolver: returns AS name + flag icon
	// ---------------------------------------------------------------------------
	async function resolveDns(ip) {
		if (!dnsActive || !isValidIPv4(ip)) return { display: ip, flag: '' };

		if (dnsCache.has(ip)) {
			return dnsCache.get(ip);
		}

		try {
			const response = await fetch('/cgi-bin/pmacct.cgi?action=location_lookup&ip=' + encodeURIComponent(ip));
			if (!response.ok) throw new Error();

			const data = await response.json();
			const result = {
				display: data.display || ip,
				flag: data.flag_icon ? '<img src="' + data.flag_icon + '" width="16" height="11" alt="" style="margin-left:5px; vertical-align:middle;">' : ''
			};

			dnsCache.set(ip, result);
			return result;
		} catch (e) {
			const fallback = { display: ip, flag: '' };
			dnsCache.set(ip, fallback);
			return fallback;
		}
	}

	// ---------------------------------------------------------------------------
	// Post-processing: replace IPs with provider name + flag
	// ---------------------------------------------------------------------------
	async function updateDnsLinks() {
		const ipLinks = \$('#tablecontainer a[data-ip]');
		for (const link of ipLinks) {
			const \$link = \$(link);
			const ip = \$link.data('ip');
			const resolved = await resolveDns(ip);

			if (resolved.display !== ip) {
				\$link.html(resolved.display + resolved.flag);
				\$link.attr('title', ip + ' → ' + resolved.display);
			} else if (resolved.flag) {
				\$link.append(resolved.flag);
			}
		}
	}

	// ---------------------------------------------------------------------------
	// Function to apply search filter on the current page
	// ---------------------------------------------------------------------------
	function applySearchOnPage() {
		const term = lastSearchTerm.toLowerCase();
		if (term === '') {
			\$('#tablecontainer tbody tr').show();
			return;
		}
		const col = parseInt(lastSearchCol);
		\$('#tablecontainer tbody tr').each(function() {
			const \$row = \$(this);
			let show = false;
			if (col === -1) {
				\$row.children('td').each(function() {
					if (\$(this).text().toLowerCase().indexOf(term) !== -1) {
						show = true;
						return false;
					}
				});
			} else {
				show = \$row.children('td').eq(col).text().toLowerCase().indexOf(term) !== -1;
			}
			\$row.toggle(show);
		});
	}

	// ---------------------------------------------------------------------------
	// Function to export table data as CSV
	// ---------------------------------------------------------------------------
	function exportToCSV() {
		if (!tableMeta || rawData.length === 0) return;
		let csv = tableMeta.headers.join(',') + "\\r\\n";
		rawData.forEach(row => {
			csv += row.map(f => '"' + (f+'').replace(/"/g, '""') + '"').join(',') + "\\r\\n";
		});
		const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
		const url = URL.createObjectURL(blob);
		const link = document.createElement('a');
		link.setAttribute('href', url);
		link.setAttribute('download', 'pmacct-top-talkers-' + new Date().toISOString().slice(0,19).replace(/:/g,'-') + '.csv');
		link.style.visibility = 'hidden';
		document.body.appendChild(link);
		link.click();
		document.body.removeChild(link);
	}

	// ---------------------------------------------------------------------------
	// Function to load data from server
	// ---------------------------------------------------------------------------
	function loadData() {
		const selectedPlugin = \$('#pluginSelect').val() || '';
		const url = 'pmacct.cgi?action=get_data' + (selectedPlugin ? '&plugin=' + encodeURIComponent(selectedPlugin) : '');
		\$('#status').html('<span style="color:orange;">Loading...</span>');
		\$.getJSON(url)
		.done(function(data) {
			tableMeta = data;
			rawData = data.raw_rows || [];
			allRows = (data.rows || []).map((row, idx) => ({ idx: idx, cells: row }));
			const now = new Date().toLocaleTimeString();
			let statusHtml = '<span style="color:green;">' + now + ' – ' + (data.rows || []).length + ' entries</span>';
			if (data.error_msg) {
				statusHtml = '<span style="color:red;">Error: ' + data.error_msg + '</span>';
			} else if (data.pipes && data.pipes.some(p => p.value === 'default')) {
				statusHtml += ' <span style="color:orange;">(Using default pipe – check pmacct.conf)</span>';
			}
			\$('#status').html(statusHtml);
			const sel = \$('#searchColumn');
			sel.empty().append('<option value="-1">All columns</option>');
			(data.headers || []).forEach((h, i) => sel.append('<option value="' + i + '">' + h.replace(/_/g, ' ') + '</option>'));
			\$('#search').val(lastSearchTerm);
			\$('#searchColumn').val(lastSearchCol);
			pageSize = parseInt(\$('#pageSize').val()) || 50;
			currentPage = 1;
			// Build dropdown for pipes
			const pipes = data.pipes || [];
			const pluginSel = \$('#pluginSelect');
			pluginSel.empty();
			if (pipes.length > 0) {
				pipes.forEach(p => pluginSel.append('<option value="' + p.value + '">' + p.name + ' (' + p.path + ')</option>'));
				pluginSel.val(data.selected_plugin || pipes[0].value);
			} else {
				pluginSel.append('<option value="">No plugins available</option>');
			}
			renderTable();
			// Auto-sort by Bytes (descending) on first load – exactly like nfdump!
			if (tableMeta.bytes_col >= 0 && currentSortCol === null) {
				currentSortCol = tableMeta.bytes_col;
				currentSortAsc = false; // false = descending = biggest first
				renderTable();
			}
		})
		.fail(function() {
			\$('#status').html('<span style="color:red;">Error loading data</span>');
			\$('#tablecontainer').html('<p style="text-align:center;color:red;">pmacct data not available (daemon not running or pipe empty)</p>');
		});
	}

	// ---------------------------------------------------------------------------
	// Event handlers for UI interactions
	// ---------------------------------------------------------------------------
	\$('#pageSize').on('change', function() { pageSize = parseInt(this.value) || 0; currentPage = 1; renderTable(); });
	\$('#search').on('input', function() { lastSearchTerm = this.value.trim(); applySearchOnPage(); });
	\$('#searchColumn').on('change', function() { lastSearchCol = this.value; applySearchOnPage(); });
	\$('#refresh').on('change', function() {
		clearInterval(refreshInterval);
		const sec = parseInt(this.value);
		if (sec > 0) refreshInterval = setInterval(loadData, sec * 1000);
	});
	\$('#manualRefresh').on('click', loadData);
	\$('#exportCsv').on('click', exportToCSV);
	\$('#pluginSelect').on('change', function() {
		loadData(); // Trigger refresh on change
	});
	window.addEventListener('beforeunload', function() { clearInterval(refreshInterval); });
	\$(document).ready(function() {
		loadData();
		\$('#refresh').val('5').trigger('change');
	});
</script>
};
&Header::closebigbox();
&Header::closepage();
exit 0;

# ===========================================================================
# Fetch and format pmacct data from memory plugin
# ===========================================================================
sub get_pmacct_data {
	my $selected_plugin = $q->param('plugin') // '';
	my $pipes_hash      = get_pmacct_memory_pipes();

	unless (keys %$pipes_hash) {
		return {
			headers         => ['No data'],
			rows            => [],
			raw_rows        => [],
			ip_colours      => [],
			bytes_col       => -1,
			src_ip_col      => -1,
			dst_ip_col      => -1,
			error_msg       => 'No memory plugins or pipes found – check pmacct.conf and daemon',
			pipes           => [],
			selected_plugin => ''
		};
	}

	unless ($selected_plugin =~ /^[a-z0-9]+$/i && exists $pipes_hash->{$selected_plugin}) {
		if ($selected_plugin) {
			log_warning("Invalid plugin attempt: $selected_plugin");
		}
		$selected_plugin = (sort keys %$pipes_hash)[0];
	}

	my $pipe = $pipes_hash->{$selected_plugin};
	unless ($pipe) {
		return {
			headers         => ['Error'],
			rows            => [],
			raw_rows        => [],
			ip_colours      => [],
			bytes_col       => -1,
			src_ip_col      => -1,
			dst_ip_col      => -1,
			error_msg       => 'Invalid plugin selected',
			pipes           => [],
			selected_plugin => ''
		};
	}

	log_info("Executing pmacct for pipe: $pipe");

	my ($in, $out, $err);
	my $pid = open3($in, $out, $err, '/usr/bin/pmacct', '-p', $pipe, '-s');
	if (!defined $pid) {
		log_error("open3 failed to execute pmacct: $!");
		return {
			headers         => ['Error'],
			rows            => [],
			raw_rows        => [],
			ip_colours      => [],
			bytes_col       => -1,
			src_ip_col      => -1,
			dst_ip_col      => -1,
			error_msg       => "Failed to execute pmacct: $!",
			pipes           => [ map { { name  => ($_ eq 'default' ? 'Default Memory Pipe' : "Memory " . ucfirst($_)),
									   value => $_,
									   path  => $pipes_hash->{$_} } } sort keys %$pipes_hash ],
			selected_plugin => $selected_plugin
		};
	}

	close $in if defined $in;
	my @lines = defined $out ? <$out> : ();
	waitpid($pid, 0);

	if ($?) {
		log_error("pmacct command failed with exit code $?");
		return {
			headers         => ['Error'],
			rows            => [],
			raw_rows        => [],
			ip_colours      => [],
			bytes_col       => -1,
			src_ip_col      => -1,
			dst_ip_col      => -1,
			error_msg       => "pmacct command failed: $?",
			pipes           => [ map { { name  => ($_ eq 'default' ? 'Default Memory Pipe' : "Memory " . ucfirst($_)),
									   value => $_,
									   path  => $pipes_hash->{$_} } } sort keys %$pipes_hash ],
			selected_plugin => $selected_plugin
		};
	}

	close $out if defined $out;
	close $err if defined $err;

	my $error_msg = '';
	unless (@lines) {
		$error_msg = 'No data available – pmacct daemon not running or pipe empty';
		return {
			headers         => ['No data'],
			rows            => [],
			raw_rows        => [],
			ip_colours      => [],
			bytes_col       => -1,
			src_ip_col      => -1,
			dst_ip_col      => -1,
			error_msg       => $error_msg,
			pipes           => [ map { { name  => ($_ eq 'default' ? 'Default Memory Pipe' : "Memory " . ucfirst($_)),
									   value => $_,
									   path  => $pipes_hash->{$_} } } sort keys %$pipes_hash ],
			selected_plugin => $selected_plugin
		};
	}

	my $header_line = shift @lines // '';
	while (@lines && $header_line !~ /\S/) {
		$header_line = shift @lines // '';
	}

	unless ($header_line =~ /\S/) {
		$error_msg = 'Error parsing header';
		return {
			headers         => ['Error parsing header'],
			rows            => [],
			raw_rows        => [],
			ip_colours      => [],
			bytes_col       => -1,
			src_ip_col      => -1,
			dst_ip_col      => -1,
			error_msg       => $error_msg,
			pipes           => [ map { { name  => ($_ eq 'default' ? 'Default Memory Pipe' : "Memory " . ucfirst($_)),
									   value => $_,
									   path  => $pipes_hash->{$_} } } sort keys %$pipes_hash ],
			selected_plugin => $selected_plugin
		};
	}

	my @headers = split(/\s+/, $header_line);

	my $bytes_col   = -1;
	my $src_ip_col  = -1;
	my $dst_ip_col  = -1;

	for my $i (0 .. $#headers) {
		$bytes_col  = $i if uc($headers[$i]) eq 'BYTES';
		$src_ip_col = $i if $headers[$i] =~ /SRC.*(IP|HOST)/i;
		$dst_ip_col = $i if $headers[$i] =~ /DST.*(IP|HOST)/i;
	}

	#@lines = splice(@lines, 0, 1000) if @lines > 1000;

	my @rows = ();
	my @raw_rows = ();
	my @ip_colours = ();
	# Packets and Bytes are minimum
	my $min_fields = 2;

	foreach my $line (@lines) {
		next unless $line =~ /\S/;

		# Ignoring pmacct -s summary
		if ($line =~ /^For\s+a\s+total\s+of:/i) {
			next;
		}

		my @fields = grep { /\S/ } split(/\s+/, $line);

		while (@fields < @headers) {
			push @fields, '';
		}

		if (@fields > @headers || @fields < $min_fields) {
			log_warning("Malformed line in pmacct output: skipping (expected ~" . scalar(@headers) . " fields, got " . scalar(@fields) . "). Offending line: '$line'");  # Debugging: Logge die Zeile
			next;
		}

		my @raw = @fields;
		my @display = map { html_escape($_) } @fields;

		if ($bytes_col >= 0 && $bytes_col < @fields && $fields[$bytes_col] =~ /^\d+$/) {
			$display[$bytes_col] = html_escape(&General::formatBytes($fields[$bytes_col]));
		}

		my $src_colour = ($src_ip_col >= 0 && $src_ip_col < @fields && $fields[$src_ip_col]) ? ipcolour($fields[$src_ip_col]) : ${Header::colourred};
		my $dst_colour = ($dst_ip_col >= 0 && $dst_ip_col < @fields && $fields[$dst_ip_col]) ? ipcolour($fields[$dst_ip_col]) : ${Header::colourred};

		push @rows, [@display];
		push @raw_rows, [@raw];
		push @ip_colours, { src => $src_colour, dst => $dst_colour };
	}
	return {
		headers         => [ @headers ],
		rows            => [ @rows ],
		raw_rows        => [ @raw_rows ],
		ip_colours      => [ @ip_colours ],
		bytes_col       => $bytes_col,
		src_ip_col      => $src_ip_col,
		dst_ip_col      => $dst_ip_col,
		error_msg       => $error_msg,
		pipes           => [ map { { name  => ($_ eq 'default' ? 'Default Memory Pipe' : "Memory " . ucfirst($_)),
								   value => $_,
								   path  => $pipes_hash->{$_} } } sort keys %$pipes_hash ],
		selected_plugin => $selected_plugin
	};
}