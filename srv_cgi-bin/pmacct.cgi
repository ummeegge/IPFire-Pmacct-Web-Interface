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
#
# Author: ummeegge
# Version: 0.8.1
# License: GPL-3.0
#===============================================================================
use strict;
use warnings;
no warnings 'once';

use CGI qw(:standard);
use JSON::PP qw(encode_json);

require '/var/ipfire/general-functions.pl';
require '/var/ipfire/header.pl';
require '/var/ipfire/lang.pl';
require '/var/ipfire/ids-functions.pl';
require '/var/ipfire/network-functions.pl';

# ---------------------------------------------------------------------------
# Build zone-to-color mapping – cached sorted list for performance
# ---------------------------------------------------------------------------
my %mainsettings = ();
&General::readhash("/var/ipfire/ethernet/settings", \%mainsettings);

my %networks = (
    "127.0.0.0/8"       => ${Header::colourfw},
    "224.0.0.0/4"       => "#A0A0A0",  # Multicast
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

# Return background colour for a given IP – fast thanks to cached sorting
sub ipcolour {
    my $ip = shift // return ${Header::colourred};

    # Quick IPv4 validation
    return ${Header::colourred} unless $ip =~ /^\d{1,3}(\.\d{1,3}){3}$/;

    foreach my $net (@sorted_networks) {
        next unless &Network::check_subnet($net);
        return $networks{$net} if &Network::ip_address_in_network($ip, $net);
    }
    return ${Header::colourred}; # Everything else = Internet (RED)
}

# Full HTML entity escaping – including single quotes (XSS-safe)
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
# CGI handling
# ---------------------------------------------------------------------------
my $q = CGI->new;

if ($q->param('action') && $q->param('action') eq 'get_data') {
    print $q->header(-type => 'application/json', -charset => 'utf-8');
    my $data = get_pmacct_data();
    print encode_json($data);
    exit 0;
}

# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------
&Header::showhttpheaders();
&Header::openpage('pmacct Traffic Accounting', 1, '');
&Header::openbigbox('100%', 'left', '');
&Header::openbox('100%', 'left', 'pmacct Live Traffic Accounting');

print qq{
<table width="100%" cellspacing="4" cellpadding="2">
<tr>
  <td width="25%"><strong>Live Update:</strong>
    <select id="refresh" style="margin-left:10px;">
      <option value="0">Off</option>
      <option value="2">2 seconds</option>
      <option value="5" selected>5 seconds</option>
      <option value="10">10 seconds</option>
    </select>
  </td>
  <td width="25%"><strong>Rows per page:</strong>
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
  <td width="30%"><strong>Search in column:</strong>
    <select id="searchColumn" style="margin-left:10px; width:200px;">
      <option value="-1">All columns</option>
    </select>
    <input type="text" id="search" style="margin-left:10px; width:280px;" placeholder="e.g. 443, 192.168, tcp..." />
  </td>
  <td width="20%" align="right">
    <input type="button" id="manualRefresh" value="Refresh now" />
    <input type="button" id="exportCsv" value="Export CSV" style="margin-left:8px;" />
    <span id="status" style="margin-left:10px; font-weight:bold; min-width:200px; display:inline-block;">Loading...</span>
  </td>
</tr>
<tr>
  <td colspan="4" align="center">
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
let refreshInterval = null;
let currentSortCol = null;
let currentSortAsc = false;
let lastSearchTerm = '';
let lastSearchCol = '-1';
let rawData = [];
let allRows = [];
let currentPage = 1;
let pageSize = 50;
let tableMeta = null;

function isValidIPv4(ip) {
    return /^(\\d{1,3}\\.){3}\\d{1,3}\$/.test(ip) &&
           ip.split('.').every(o => parseInt(o,10) <= 255);
}

function sortTable(col) {
    currentSortAsc = (currentSortCol === col) ? !currentSortAsc : false;
    currentSortCol = col;
    renderTable();
}

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

function renderTable() {
    if (!tableMeta || allRows.length === 0) {
        \$('#tablecontainer').html('<p style="text-align:center;color:red;">No data available – pmacct daemon not running or pipe empty</p>');
        \$('#pagination').empty();
        return;
    }

    // === SORTING: natural IPv4 → numeric → string ===
    if (currentSortCol !== null) {
        allRows.sort((a, b) => {
            let A = rawData[a.idx][currentSortCol];
            let B = rawData[b.idx][currentSortCol];

            // Natural IPv4 sorting for IP columns
            if (currentSortCol === tableMeta.src_ip_col || currentSortCol === tableMeta.dst_ip_col) {
                const ipToNum = ip => ip.split('.').map(o => parseInt(o, 10) || 0);
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

            // String fallback
            return A.localeCompare(B) * (currentSortAsc ? 1 : -1);
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
            let content = cell || ' ';
            let bg = '';

            // Defense-in-depth escaping
            content = content.replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));

            if (tableMeta.src_ip_col >= 0 && tableMeta.dst_ip_col >= 0 &&
                (colIdx === tableMeta.src_ip_col || colIdx === tableMeta.dst_ip_col)) {
                const ipc = tableMeta.ip_colours[rowObj.idx];
                if (ipc) bg = (colIdx === tableMeta.src_ip_col) ? ipc.src : ipc.dst;

                if (isValidIPv4(content)) {
                    content = '<a href="/cgi-bin/ipinfo.cgi?ip=' + encodeURIComponent(content) +
                              '" target="_blank" style="color:#FFFFFF; font-weight:bold; text-decoration:underline;">' +
                              content + '</a>';
                }
            }

            html += '<td class="base" style="background-color:' + bg + ';">' + content + '</td>';
        });
        html += '</tr>';
    });
    html += '</tbody></table>';
    \$('#tablecontainer').html(html);
    updatePagination(allRows.length);
    applySearchOnPage();
}

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

function loadData() {
    \$('#status').html('<span style="color:orange;">Loading...</span>');
    \$.getJSON('pmacct.cgi?action=get_data')
    .done(function(data) {
        tableMeta = data;
        rawData   = data.raw_rows;
        allRows   = data.rows.map((row, idx) => ({ idx: idx, cells: row }));
        const now = new Date().toLocaleTimeString();
        \$('#status').html('<span style="color:green;">' + now + ' – ' + data.rows.length + ' entries</span>');

        const sel = \$('#searchColumn');
        sel.empty().append('<option value="-1">All columns</option>');
        data.headers.forEach((h, i) => sel.append('<option value="' + i + '">' + h.replace(/_/g, ' ') + '</option>'));

        \$('#search').val(lastSearchTerm);
        \$('#searchColumn').val(lastSearchCol);
        pageSize = parseInt(\$('#pageSize').val()) || 50;
        currentPage = 1;
        renderTable();
    })
    .fail(function() {
        \$('#status').html('<span style="color:red;">Error loading data</span>');
        \$('#tablecontainer').html('<p style="text-align:center;color:red;">pmacct data not available (daemon not running or pipe empty)</p>');
    });
}

// Classic jQuery handlers – proper 'this' binding guaranteed
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
    my @lines = `/usr/bin/pmacct -p /var/spool/pmacct/plugin1.pipe -s 2>/dev/null`;

    unless (@lines) {
        return {
            headers => ['No data'], rows => [], raw_rows => [], ip_colours => [],
            bytes_col => -1, src_ip_col => -1, dst_ip_col => -1
        };
    }

    my $header_line = shift @lines;
    while (defined $header_line && $header_line !~ /\S/ && @lines) {
        $header_line = shift @lines;
    }

    unless ($header_line && $header_line =~ /\S/) {
        return {
            headers => ['Error parsing header'], rows => [], raw_rows => [], ip_colours => [],
            bytes_col => -1, src_ip_col => -1, dst_ip_col => -1
        };
    }

    my @headers = split(/\s+/, $header_line);

    my $bytes_col   = -1;
    my $src_ip_col  = -1;
    my $dst_ip_col  = -1;

    for my $i (0 .. $#headers) {
        $bytes_col   = $i if uc($headers[$i]) eq 'BYTES';
        $src_ip_col  = $i if $headers[$i] =~ /SRC.*(IP|HOST)/i;
        $dst_ip_col  = $i if $headers[$i] =~ /DST.*(IP|HOST)/i;
    }

    @lines = splice(@lines, 0, 1000) if @lines > 1000;

    my @rows       = ();
    my @raw_rows   = ();
    my @ip_colours = ();

    foreach my $line (@lines) {
        next unless $line =~ /\S/;
        my @fields = split(/\s+/, $line);
        next unless scalar(@fields) >= scalar(@headers);

        my @display = map { html_escape($_) } @fields;
        my @raw     = @fields;

        if ($bytes_col >= 0 && $fields[$bytes_col] =~ /^\d+$/) {
            $display[$bytes_col] = html_escape(&General::formatBytes($fields[$bytes_col]));
        }

        my $src_colour = ($src_ip_col >= 0) ? ipcolour($fields[$src_ip_col] // '') : ${Header::colourred};
        my $dst_colour = ($dst_ip_col >= 0) ? ipcolour($fields[$dst_ip_col] // '') : ${Header::colourred};

        push @rows,       [ @display ];
        push @raw_rows,   [ @raw ];
        push @ip_colours, { src => $src_colour, dst => $dst_colour };
    }

    return {
        headers     => [ @headers ],
        rows        => [ @rows ],
        raw_rows    => [ @raw_rows ],
        ip_colours  => [ @ip_colours ],
        bytes_col   => $bytes_col,
        src_ip_col  => $src_ip_col,
        dst_ip_col  => $dst_ip_col
    };
}