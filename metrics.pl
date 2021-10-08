#!/usr/bin/env perl
# find statistics on ipfw rules based on comments in milliseconds
# example line:
# 20113 deny ip from 185.128.41.50 to any // 1632206818537

$BASE_RULE = 20000;
$NUM_SLOTS = 128;

die "you must be root\n" if $>;
$pipe = sprintf("/sbin/ipfw list %d-%d", $BASE_RULE, $BASE_RULE+$NUM_SLOTS-1);
open(PIPE, "$pipe |") || die "pipe to ipfw failed\n";

while(<PIPE>) {
	next unless m#//#;
	m#//\s(\d+)$#;
	$milli = $1;
	if (0 == $min || $milli < $min) {
		$min = $milli;
	} elsif ($milli > $max) {
		$max = $milli;
	}
	push(@measurements, $milli);
	$total += $milli;

	chomp;
	print $_ . "\t# " . localtime($milli/1000) . "\n";
}

sub diff {
	my ($min, $max) = @_;
	my $diffseconds = int(($max-$min)/1000);
	my $diffhours = int($diffseconds/3600);
	my $diffminutes = int(($diffseconds % 3600)/60);

	print "$diffhours hours $diffminutes minutes\n";
	return ($diffhours, $diffminutes, $diffseconds);
}

@sorted = sort @measurements;
$now = time() * 1000;

print "samples = " . @measurements . "\n";

print "range = ";
diff ($min, $max);

$oldest = $sorted[0];
print "oldest = ";
diff ($oldest, $now);

$youngest = $sorted[$#sorted];
print "youngest = ";
diff ($youngest, $now);

$average = int($total/@measurements);
print "average age = ";
diff($average, $now);

$median = $sorted[int(@measurements/2)];
print "median age = ";
diff($median, $now);

$p95 = $sorted[int(@measurements*.95)];
print "95th percentile = ";
diff($p95, $now);
