#!/usr/bin/perl
# Call mtr in out-of-source build
$ENV{MTR_BINDIR} = '/root/eval/mysql-server-mysql-5.6.35/bld';
chdir('/root/eval/mysql-server-mysql-5.6.35/mysql-test');
exit(system($^X, '/root/eval/mysql-server-mysql-5.6.35/mysql-test/mysql-test-run.pl', @ARGV) >> 8);
