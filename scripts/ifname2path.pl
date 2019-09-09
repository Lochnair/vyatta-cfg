#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5/";
use Vyatta::Interface;

my $ifname = $ARGV[0];

my $intf = new Vyatta::Interface($ifname);
unless ($intf) {
    die "Invalid interface [$ifname]\n"
}
  
my $path = $intf->path();
print $path;
