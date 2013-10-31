requires 'parent', 0;
requires 'POSIX', 0;
requires 'POSIX::2008', 0;
requires 'Digest::SHA', 0;
requires 'Digest::HMAC', 0;
requires 'List::UtilsBy', 0;
requires 'HTTP::StreamParser', '>= 0.100';
requires 'URI', 0;
requires 'URI::QueryParam', 0;
requires 'URI::Escape', 0;
requires 'Mixin::Event::Dispatch', '>= 1.000';

on 'test' => sub {
	requires 'Test::More', '>= 0.98';
	requires 'Test::Fatal', '>= 0.010';
	requires 'Dir::Self', 0;
	requires 'Path::Tiny', 0;
};

