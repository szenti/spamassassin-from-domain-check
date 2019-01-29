#!/usr/bin/perl
use strict;
use warnings;

package FromDomainCheck;
use Mail::SpamAssassin::Plugin;
use Net::DNS::Resolver;

my $MAIL_OK = 0;
my $MAIL_SPAM = 1;
my $ACTION_UNRESOLVABLE_HOSTNAME = $MAIL_OK; # if you want to drop these emails, set it to $MAIL_SPAM
my $DOMAIN_PATTERN = q"\@([\d\w\-\.]+)";
my $RECORD_TYPE_A = "A";

my %IP_BLACKLIST = (
    "185.140.110.3" => 1,
    "185.207.8.14" => 1,
    "185.207.11.245" => 1,
    "185.207.8.246" => 1,
    "174.129.25.170" => 1
);

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my ($class, $mailsa) = @_;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);

  $self->register_eval_rule ("check_from_domain_ip");
  return $self;
}

sub get_from_domain {
  my ($message) = @_;
  my $from_address = lc($message->get('From:addr'));

  $from_address =~ /$DOMAIN_PATTERN/;
  my $from_domain = $1; 
}

sub is_ip_blacklisted {
  my ($ip_address) = @_;
  return IP_BLACKLIST{$ip_address} == 1;
}

sub check_from_domain_ip {
  my ($self, $message) = @_;
  my $resolver = Net::DNS::Resolver->new;

  my $message_from_domain = get_from_domain($message);
  my $result = $resolver->query($message_from_domain, $RECORD_TYPE_A);

  if (!$result) {
    return $ACTION_UNRESOLVABLE_HOSTNAME;
  }

  foreach my $record ($result->answer) {
    if (is_ip_blacklisted($record->address)) {
      return $MAIL_SPAM;
    }
  }

  return $MAIL_OK;
}

1; # required by perl
