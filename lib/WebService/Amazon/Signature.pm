package WebService::Amazon::Signature;
# ABSTRACT: 
use strict;
use warnings;

our $VERSION = '0.001';

=head1 NAME

WebService::Amazon::Signature -

=head1 SYNOPSIS

=head1 DESCRIPTION

=cut

use WebService::Amazon::Signature::v4;

=head1 METHODS

=cut

sub new {	
	my $class = shift;
	my %args = @_;
	my $version = delete $args{version} || 4;
	my $pkg = 'WebService::Amazon::Signature::v' . $version;
	if(my $code = $pkg->can('new')) {
		$class = $pkg if $class eq __PACKAGE__;
		return $code->($class, %args)
	}
	die "No support for version $version";
}

1;

__END__

=head1 SEE ALSO

=over 4

=item * L<Net::Amazon::Signature::V4>

=back

=head1 AUTHOR

Tom Molesworth <cpan@entitymodel.com>

=head1 LICENSE

Copyright Tom Molesworth 2011. Licensed under the same terms as Perl itself.

