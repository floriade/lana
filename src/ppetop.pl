#!/usr/bin/perl
# apt-get install libcurses-ui-perl

use warnings;
use strict;
use Curses::UI;

my @files;
my %stats;
my ($cui, $win, $widget);
my $text;

pre();
main();
exit;

sub pre
{
	$text = "";
	opendir(LD, "/proc/net/lana/") or die $!;
	@files = grep(/ppe\d/, readdir(LD));
	closedir(LD);
	if ($#files + 1 - $[ == 0) {
		die "LANA not running?!";
	}
}

sub fetch_stats
{
	foreach my $file (@files) {
		my %curr;
		for (keys %curr) {
			delete $curr{$_};
		}
		open(LH, "<", "/proc/net/lana/$file") or die $!;
		while (<LH>) {
			if (/(packets|bytes|errors|drops):\s+(\d+)/) {
				$curr{$1} += $2;
			}
		}
		close(LH);
		for (keys %curr) {
			my $tmp = ${${$stats{$file}}{$_}}{new};
			${${$stats{$file}}{$_}}{old} = $tmp;
			${${$stats{$file}}{$_}}{new} = $curr{$_};
		}
	}
}

sub print_stats
{
	$text = "LANA ppe top:\n\n";
	foreach my $file (@files) {
		my $pps = ${${$stats{$file}}{packets}}{new} -
			  ${${$stats{$file}}{packets}}{old};
		my $mbs = int((${${$stats{$file}}{bytes}}{new} -
			       ${${$stats{$file}}{bytes}}{old}) /
			      (1 << 20));
		my $eps = ${${$stats{$file}}{errors}}{new} -
			  ${${$stats{$file}}{errors}}{old};
		my $dps = ${${$stats{$file}}{drops}}{new} -
			  ${${$stats{$file}}{drops}}{old};
		$text .= "$file:\n";
		$text .= "\t$pps\tpkts/s\n";
		$text .= "\t$mbs\tMiB/s\n";
		$text .= "\t$dps\tdrops/s\n";
		$text .= "\t$eps\terr/s\n\n";
	}	
	$widget->text($text);
}

sub exit_bind
{
	exit;
}

sub main_stats
{ 
	fetch_stats();
	print_stats();
}

sub main 
{
	fetch_stats();
	$text = "Collecting statistics, please wait ...\n";
	$cui = new Curses::UI(-color_support => 1);
	$cui->set_binding(\&exit_bind, "\cQ", "\cC");
	$win = $cui->add('screen', 'Window',
			 -border => 0,
			 -ipad => 0,);
	$widget = $win->add('ppetop', 'TextViewer',
			    -border => 1,
			    -wrapping => 0,
			    -text => $text,);
	$widget->clear_binding('loose_focus');
	$widget->focus;
	$cui->set_timer('ppetop_stats', \&main_stats, 1);
	$cui->enable_timer('ppetop_stats');
	$cui->mainloop;
}
