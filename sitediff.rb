#!/usr/bin/env ruby

#
# Sitediff, a tool to compare local files with those served by a site.
#
# Find the latest version at https://github.com/digininja/sitediff
# and a full write up at https://digi.ninja/projects/sitediff.php
#
#
# Author:: Robin Wood (robin@digi.ninja) (https://digi.ninja)
# Copyright:: Copyright (c) Robin Wood 2016
# Licence:: CC-BY-SA 2.0 or GPL-3+
#

VERSION = "1.0 (Lazy Day)"

puts "sitediff #{VERSION} Robin Wood (robin@digi.ninja) (https://digi.ninja/)\n\n"

begin
	require "filesize"
	require 'digest'
	require 'getoptlong'
	require 'net/http'
	require 'openssl'
	require_relative 'string'
rescue LoadError => e
	# Catch error and provide feedback on installing gem
	if e.to_s =~ /cannot load such file -- (.*)/
		missing_gem = $1
		puts "\nError: #{missing_gem} gem not installed\n"
		puts "\t Use: 'gem install #{missing_gem}' to install the required gem\n\n"
		puts "\t Or: bundle install\n\n"
		exit 2
	else
		puts "There was an error loading the gems:\n"
		puts e.to_s
		exit 2
	end
end

opts = GetoptLong.new(
		['--help', '-h', GetoptLong::NO_ARGUMENT],
		['--keep', '-k', GetoptLong::NO_ARGUMENT], # maybe in a future release
		['--match-only', '-m', GetoptLong::NO_ARGUMENT],
		['--path', "-p", GetoptLong::REQUIRED_ARGUMENT],
		['--url', "-u", GetoptLong::REQUIRED_ARGUMENT],
		['--ua', GetoptLong::REQUIRED_ARGUMENT],
		['--auth_user', GetoptLong::REQUIRED_ARGUMENT],
		['--auth_pass', GetoptLong::REQUIRED_ARGUMENT],
		['--auth_type', GetoptLong::REQUIRED_ARGUMENT],
		['--header', "-H", GetoptLong::REQUIRED_ARGUMENT],
		['--proxy_host', GetoptLong::REQUIRED_ARGUMENT],
		['--proxy_port', GetoptLong::REQUIRED_ARGUMENT],
		['--proxy_username', GetoptLong::REQUIRED_ARGUMENT],
		['--proxy_password', GetoptLong::REQUIRED_ARGUMENT],
		["--verbose", "-v", GetoptLong::NO_ARGUMENT]
)

# Display the usage
def usage
	puts "Usage: sitediff [OPTION]
	--help, -h: show help
	--path, -p path: the path for the source
	--url, -u URL: the base URL
	--ua user-agent: user agent to send
	--match-only, -m: only show matches

	Authentication
		--auth_type: digest or basic
		--auth_user: authentication username
		--auth_pass: authentication password

	Proxy Support
		--proxy_host: proxy host
		--proxy_port: proxy port, default 8080
		--proxy_username: username for proxy, if required
		--proxy_password: password for proxy, if required

	Headers
		--header, -H: in format name:value - can pass multiple

	--verbose, -v: verbose

"
	exit 0
end

debug = false
verbose = false
ua = "Sitediff spider #{VERSION} - https://digi.ninja/projects/sitediff.php"
base_url = nil
path = nil
keep = false
match_only = false

auth_type = nil
auth_user = nil
auth_pass = nil

proxy_host = nil
proxy_port = nil
proxy_username = nil
proxy_password = nil

# headers will be passed in in the format "header: value"
# and there can be multiple
headers = []

begin
	opts.each do |opt, arg|
		case opt
			when '--help'
				usage
			when "--path"
				if !File.directory?(arg)
					puts "#{arg} is not a directory\n"
					exit 1
				end

				path = arg
			when "--keep"
				keep = true
			when "--url"
				# Must have protocol
				base_url = arg
				base_url = "http://#{base_url}" unless base_url =~ /^http(s)?:\/\//
				base_url = base_url + "/" unless base_url =~ /.*\/$/
			when '--match-only'
				match_only = true
			when '--ua'
				ua = arg
			when '--verbose'
				verbose = true
			when "--header"
				headers << arg
			when "--proxy_password"
				proxy_password = arg
			when "--proxy_username"
				proxy_username = arg
			when "--proxy_host"
				proxy_host = arg
			when "--proxy_port"
				proxy_port = arg.to_i
			when "--auth_pass"
				auth_pass = arg
			when "--auth_user"
				auth_user = arg
			when "--auth_type"
				if arg =~ /(digest|basic)/i
					auth_type = $1.downcase
					if auth_type == "digest"
						begin
							require "net/http/digest_auth"
						rescue LoadError => e
							# Catch error and provide feedback on installing gem
							puts "\nError: To use digest auth you require the net-http-digest_auth gem\n"
							puts "\t Use: 'gem install net-http-digest_auth'\n\n"
							exit 2
						end
					end
				else
					puts "\nInvalid authentication type, please specify either basic or digest\n\n"
					exit 1
				end
		end
	end
rescue
	puts
	usage
end

if auth_type && (auth_user.nil? || auth_pass.nil?)
	puts "\nIf using basic or digest auth you must provide a username and password\n\n"
	exit 1
end

if auth_type.nil? && (!auth_user.nil? || !auth_pass.nil?)
	puts "\nAuthentication details provided but no mention of basic or digest\n\n"
	exit 1
end

if base_url.nil?
	puts "You must specify the URL to test (--url)\n"
	exit 1
end

if path.nil?
	puts "You must specify the path for the local files (--path)\n"
	exit 1
end

header_hash = {}

if headers.length > 0 then
	headers.each do |header|
		header_split = header.split(":")
		if (header_split.count == 2)
			header_hash[header_split[0].strip] = header_split[1].strip
		else
			puts "Invalid header: " + header.inspect
		end
	end
end

unless ua.nil?
	header_hash['User-Agent'] = ua
end

match_count = 0
total_count = 0

Dir.chdir(path)
Dir.glob('**/*').each do |f|
	if File.file?(f)
		local_file_size = File.size(f)
		url = "#{base_url}#{f}"
		puts "Testing: #{url}" if verbose

		uri = URI.parse(url)

		# Shortcut
		#response = Net::HTTP.get_response(uri)

		if proxy_host.nil?
			http = Net::HTTP.new(uri.host, uri.port)

			if uri.scheme == 'https'
				http.use_ssl = true
				http.verify_mode = OpenSSL::SSL::VERIFY_NONE
			end
		else
			proxy = Net::HTTP::Proxy(proxy_host, proxy_port, proxy_username, proxy_password)
			begin
				if uri.scheme == 'https'
					http = proxy.start(uri.host, uri.port, :use_ssl => true, :verify_mode => OpenSSL::SSL::VERIFY_NONE)
				else
					http = proxy.start(uri.host, uri.port)
				end
			rescue => e
				puts "\nFailed to connect to the proxy (#{proxy_host}:#{proxy_port})\n\n"
				exit 1
			end
		end

		request = Net::HTTP::Get.new(uri.request_uri)
		header_hash.each_pair do |header, value|
			request[header] = value
		end

		if auth_type
			case auth_type
				when "digest"
					uri.user = auth_user
					uri.password = auth_pass

					res = http.request request

					if res['www-authenticate']
						digest_auth = Net::HTTP::DigestAuth.new
						auth = digest_auth.auth_header uri, res['www-authenticate'], 'GET'

						request = Net::HTTP::Get.new uri.request_uri
						request.add_field 'Authorization', auth
					end

				when "basic"
					request.basic_auth auth_user, auth_pass
			end
		end

		begin
			response = http.request request
		rescue => e
			puts "There was a problem connecting to the server, please check the URL."
			exit 1
		end

		total_count += 1

		puts "Response code: #{response.code}" if verbose
		response_code = response.code.to_i

		case response_code
			when 500
				puts("#{f}: Internal server error".negative) unless match_only
			when 404
				puts("#{f}: File not found on site".negative) unless match_only
			when 401
				puts("#{f}: Authentication required".negative) unless match_only
			when 301, 302
				puts("#{f}: Redirect found to #{response['location']}".negative) unless match_only
			when 200
				response_length = response.body.length
				puts "Local file size: #{local_file_size}" if verbose
				puts "Response length: #{response_length}" if verbose
				if local_file_size != response_length then
					puts("#{f}: File found but different file size - local #{Filesize.from(local_file_size.to_s + " B").pretty} vs remote #{Filesize.from(response_length.to_s + " B").pretty}".neutral) unless match_only
				else
					sha256 = Digest::MD5.file f
					local_md5 = sha256.hexdigest
					puts "Local MD5: #{local_md5}" if verbose

					remote_md5 = Digest::MD5.hexdigest response.body
					puts "Local MD5: #{remote_md5}" if verbose

					if local_md5 == remote_md5 then
						puts "#{f}: Matching file found - #{url}".positive
						match_count += 1
					else
						puts "#{f}: File exists and is same size but contents differ".neutral unless match_only
					end
				end
			else
				puts("#{f}: Response code #{response_code}".negative) unless match_only
		end
	end
end
puts
puts "Summary:"
puts "#{total_count} files checked"
puts "#{match_count} files matched"
puts
