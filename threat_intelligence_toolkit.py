#!/usr/bin/env python3
#
# COPYRIGHT 2022 BY EXTRAHOP NETWORKS, INC.
# 
# This file is subject to the terms and conditions defined in
# file 'LICENSE', which is part of this source code package.
#
# Description: Threat Intelligence Toolkit - Automate generating or pulling threat intelligence Structured Threat 
# Information Expression (STIX) files from a flat file or from a TAXII server and uploading a threat collection to 
# an ECA and multiple EDAs via the REST API. By uploading STIX files, you can add a threat collection to your ExtraHop 
# Discover and Command appliances. Threat collections enable you to identify suspicious hosts, IP addresses, and URIs 
# on your network
#
# Usage: Specify an output directory, threat collection name, ECA/EDA details, and other optional config via
# the command line then the script either generates a STIX file or polls the TAXII server (defaults to EclecticIQ
# OpenTAXII intel feed), saves the stix files in a gzipped tar file (tgz), and uploads the threat collection to the
# specified Reveal(x) ECA/EDAs
#
# Note: This script solely serves as example code and is made available without any support or warranty.
#
# Version 1.3.6

import cabby
import requests
import urllib3
import validators
import ipaddress
import datetime
import pytz
import argparse
import os
import sys
import tarfile
import shutil
import logging
from cybox.objects.uri_object import URI
from cybox.objects.domain_name_object import DomainName
from cybox.objects.address_object import Address
from cybox.utils.caches import cache_clear
from stix.core import STIXPackage, STIXHeader
from stix.indicator.indicator import Indicator

# parse command line arguments
def parse_command_line_args():
	
	argparser = argparse.ArgumentParser()

	argparser.add_argument('-o', '--output-dir', action='store', dest='output_dir', help='Existing directory to output tgz containing stix files', required=True, metavar='OUTPUT_DIRECTORY')
	argparser.add_argument('-tc', '--threatcollection-name', action='store', dest='threat_collection_name', help='Name for the ExtraHop threat collection', required=True)
	# options below are for specifying a TAXII server to pull from
	argparser.add_argument('--taxii-server', action='store', dest='taxii_server', default=[], nargs=3, help='TAXII server to poll TI info from, format: host discovery_path use_https', metavar=('TAXII_HOST', 'DISCOVERY_PATH', 'USE_HTTPS'))
	argparser.add_argument('--taxii-collections', action='store', dest='taxii_collections', default=[], nargs='*', help='One or more desired TAXII collection names to poll', metavar='TAXII_COLLECTION_NAME')
	argparser.add_argument('--days', action='store', dest='days_to_poll', default=30, type=int, help='Number of days to poll from the past')
	argparser.add_argument('--basic-user', action='store', dest='basic_user', help='Username, used in basic auth', metavar='BASIC_USERNAME')
	argparser.add_argument('--basic-pw', action='store', dest='basic_pw', help='Password, used in basic auth', metavar='BASIC_PASSWORD')
	# options below are for generating a STIX file from a flat file
	argparser.add_argument('--generate-stix', action='store_true', dest='generate_stix', default=False, help='Create a stix file from a flat file. Requires that --input-file and --type are set.')
	argparser.add_argument('--input-file', action='store', dest='input_file', help='Full path of delimited list file. Also accepts a URL to a file. Ignored if --generate-stix is not set.', metavar='INPUT_FILE')
	argparser.add_argument('--list-type', action='store', dest='list_type', choices=['ip','domain', 'url'], help='Type of the input items in the provided list (list must all be the same type), allowed values: ip, domain, url. Ignored if --generate-stix is not set.', metavar='LIST_TYPE')
	argparser.add_argument('--delimiter', action='store', dest='delimiter', help='Delimiter for the input list file. Ignored if --generate-stix is not set.', default='\n', metavar='INPUT_FILE')
	argparser.add_argument('--list-name', action='store', dest='list_name', help='Name of the list or provider to be used in the created stix file. Ignored if --generate-stix is not set.', default='Threat Intel List', metavar='LIST_NAME')
	argparser.add_argument('--validate', action='store_true', dest='validate_input', default=False, help='Validate each Domain/URL before adding to generated stix file (beta). Requires that --generate-stix is set.')
	# option below are for uploading to eca/eda(s)
	argparser.add_argument('--eca', action='store', dest='eca', default=[], nargs=3, help='One ECA to push threat intel collection, format: host apikey verify_cert', metavar=('HOST', 'APIKEY', 'VERIFY_CERT'))
	argparser.add_argument('--eda', action='append', dest='edas', default=[], nargs=3, help='One or more EDAs to push threat intel collection, format: host apikey verify_cert', metavar=('HOST', 'APIKEY', 'VERIFY_CERT'))
	argparser.add_argument('--clean-up', action='store_true', dest='clean_up', default=False, help='Remove the local threat collection .tgz file after successfully uploading, recommended when running on cron. Requires that --eca or --eda is set.')
	# debug output
	argparser.add_argument('-v', '--verbose', action='store_true', dest='verbose', default=False, help='Verbose mode, prints out service and collection details as well as running info')

	args = argparser.parse_args()

	if args.generate_stix:
		if not args.input_file or not args.list_type:
			argparser.error("the following arguments are required when --generate-stix is set: --input-file and --list-type")

	return args

# strip all non alphanumeric chars from a string
def strip_non_alphanum(input_str):
	return ''.join(char for char in input_str if char.isalnum())

# convert string to boolean and return True when unsure
def str_to_bool(input_str):
	return input_str.lower() not in ['false', 'f', '0', 'n', 'no']

# send a PUT request to an EDA or ECA threatcollections/{id} endpoint
def threatcollection_api_request(eh_host, eh_apikey, eh_verify_cert, threatcollection_name, file_name, file_path, verbose):

	if verbose:
		logging.info("===============")
		logging.info("== UPLOADING ==")
		logging.info("===============")

	user_key = strip_non_alphanum(threatcollection_name)

	headers = {'Accept': 'application/json', 'Authorization': "ExtraHop apikey={}".format(eh_apikey)}

	url = "https://{}/api/v1/threatcollections/~{}".format(eh_host, user_key)

	# configure tgz for multipart file upload
	file_body = {'file': (file_name, open(file_path, 'rb')), 'name': threatcollection_name} 

	# log InsecureRequestWarning if making an unverified https request
	if not eh_verify_cert:
		logging.warning("InsecureRequestWarning: Unverified HTTPS request is being made. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings InsecureRequestWarning")

	try:
		# send PUT request to create or update
		r = requests.put(url, headers=headers, files=file_body, verify=eh_verify_cert)
	except Exception as e:
		logging.error("Issue encountered while sending an API request to {}. Details: {}".format(url, e))
		raise

	# handle non 200 response
	if r.status_code >= 200 and r.status_code < 300:
		logging.info("Successfully uploaded {} to {} as threatcollection named {} with user_key {}".format(file_name, eh_host, threatcollection_name, user_key))
	else:
		logging.error(("Non-200 status code from ExtraHop API request. Status code: {}, URL: {}, Response: {}".format(r.status_code, url, r.text)))
		raise ValueError("Non-200 status code from ExtraHop API request. Status code: {}, URL: {}, Response: {}".format(r.status_code, url, r.text))
	return

# generate stix files from a flat file or URL to a flat file
def generate_stix_file(input_file, list_type, delimiter, list_name, tc_name, tmp_dir, validate, verbose):
	# observable limit per generated stix file
	OBSERVABLES_PER_STIX_FILE = 3000

	if verbose:
		logging.info("=====================")
		logging.info("== GENERATING STIX ==")
		logging.info("=====================")
	
	# download or open input file
	if validators.url(input_file):
		res = requests.get(input_file)
		items = res.text.split(delimiter)
	else:
		# exit if input file doesn't exist
		if not os.path.isfile(input_file):
			logging.error("Supplied input file '{}' doesn't exist".format(input_file))
			sys.exit("Error: Supplied input file '{}' doesn't exist".format(input_file))
		else:
			with open(input_file, 'r') as f:
				items = f.read().split(delimiter)
	logging.info("Successfully parsed input file at {}".format(input_file))

	# slice input into batches
	for batch_num, index in enumerate(range(0, len(items), OBSERVABLES_PER_STIX_FILE), 1):
		# slice handles out of bounds indices gracefully
		batch_items = items[index:index + OBSERVABLES_PER_STIX_FILE]

		# create the STIX Package
		package = STIXPackage()

		# create the STIX Header and add a description
		header = STIXHeader()
		package.stix_header = header

		reporttime = datetime.datetime.utcnow().strftime('%m/%d/%Y %H:%M:%S %Z')

		# create indicator for each item in the batch
		for item in batch_items:
			item = item.strip()

			# basic filtering of empty items and comments
			if not item or item.startswith(('#', '//', '--')):
				continue

			if list_type == 'ip':
				indicator_obj = Address()
				# attempt to parse as an ip address
				try:
					parsed_ip = ipaddress.ip_address(item)
					if parsed_ip.version == 4:
						indicator_obj.category = Address.CAT_IPV4
					elif parsed_ip.version == 6:
						indicator_obj.category = Address.CAT_IPV6
					else:
						logging.warning("Unknown IP Address version type: {} - skipping".format(parsed_ip.version))
						continue
				except ValueError:
					# if ip address parsing fails then attempt to parse as an ip network
					try:
						parsed_ip = ipaddress.ip_network(item, strict=False)
						indicator_obj.category = Address.CAT_CIDR
					except ValueError:
						logging.warning("IP Address {} is neither an IPv4, IPv6, nor CIDR - skipping".format(item))
						continue
				indicator_obj.address_value = str(parsed_ip)
				indicator_obj.condition = "Equals"
				indicator_type = "IP Watchlist"
				# customizable components below
				indicator_title = "IP: {}"
				indicator_description = "IP {} reported from {}"
			elif list_type == 'domain':
				# validate domain
				if validate and not validators.domain(item):
					logging.warning("Invalid domain: {} - skipping".format(item))
					continue
				indicator_obj = DomainName()
				indicator_obj.value = item
				indicator_type = "Domain Watchlist"
				# customizable components below
				indicator_title = "Domain: {}"
				indicator_description = "Domain {} reported from {}"
			elif list_type == 'url':
				# validate url
				if validate and not validators.url(item):
					logging.warning("Invalid url: {} - skipping".format(item))
					continue
				indicator_obj = URI()
				indicator_obj.value = item
				indicator_obj.type_ =  URI.TYPE_URL
				indicator_obj.condition = "Equals"
				indicator_type = "URL Watchlist"
				# customizable components below
				indicator_title = "URL: {}"
				indicator_description = "URL {} reported from {}"
			else:
				# invalid input type
				logging.error("invalid input type encountered")
				raise Exception('Error: invalid input type encountered')

			# create a basic Indicator object from the item
			indicator = Indicator()
			indicator.title = indicator_title.format(str(item))
			indicator.description = indicator_description.format(str(item), list_name)
			indicator.add_indicator_type(indicator_type)
			indicator.set_producer_identity(list_name)
			indicator.set_produced_time(str(reporttime))
			indicator.add_observable(indicator_obj)

			# add the indicator to the stix package
			package.add_indicator(indicator)

		# save each batch in a separate stix file with the filename ending ..._part_N.stix
		collection_filename = "{}_part_{}.stix".format(strip_non_alphanum(tc_name), batch_num)
		with open(os.path.join(tmp_dir, collection_filename), 'wb') as f:
			f.write(package.to_xml())
		logging.info("Successfully created stix file {}".format(collection_filename))

		# clear cybox cache to prevent an Out of Memory error
		# https://cybox.readthedocs.io/en/stable/api/cybox/core/object.html#cybox.core.object.Object
		cache_clear()
			
	return 

# poll a taxii server for stix files
def poll_taxii_server(taxii_server, basic_user, basic_pw, taxii_collections, days_to_poll, tmp_dir, verbose):
	# if no taxii server details are specified then default to the OTX AlienVault/AT&T Cybersecurity threat intel feed
	if not taxii_server:
		taxii_server = ["otx.alienvault.com", "/taxii/discovery", "True"]

	try:
		# handle taxii server port if supplied
		taxii_server_port = None
		if ':' in taxii_server[0]:
			taxii_server[0], taxii_server_port = taxii_server[0].split(':')
			
		# setup taxii client
		taxii_client = cabby.create_client(
			host=taxii_server[0],
			port=taxii_server_port,
			discovery_path=taxii_server[1],
			use_https=str_to_bool(taxii_server[2]),
			version='1.1')

		# configure basic auth if supplied
		if basic_user and basic_pw:
			taxii_client.set_auth(username=basic_user, password=basic_pw)
			if verbose:
				logging.info("TAXII client is using basic authentication")

		# retrieve service and collection info from the taxii server
		services = taxii_client.discover_services()
		collections = taxii_client.get_collections()
	except Exception as e:
		logging.error("Issue encountered while setting up or querying with the TAXII client. Details: {}".format(e))
		raise

	# verbose taxii server info
	if verbose:
		logging.info("==============")
		logging.info("== SERVICES ==")
		logging.info("==============")
		for service in services:
			logging.info("Service type={s.type}, address={s.address}, available={s.available}, message={s.message}, version={s.version}, protocol={s.protocol}".format(s=service))

		logging.info("=================")
		logging.info("== COLLECTIONS ==")
		logging.info("=================")
		for collection in collections:
				logging.info("Collection name={c.name}, description={c.description}, available={c.available}".format(c=collection))

		logging.info("=============")
		logging.info("== POLLING ==")
		logging.info("=============")

	# if specified, filter only the supplied collection(s) 
	if taxii_collections:
		collections = filter(lambda collection: collection.name in taxii_collections, collections)

	# poll each collection for the specified timeframe and write a stix file to disk
	for collection in collections:
		try:
			# poll the collection, it may return zero or more content blocks
			content_blocks = taxii_client.poll(collection.name, begin_date=pytz.utc.localize(datetime.datetime.today()) - datetime.timedelta(days=days_to_poll), end_date=pytz.utc.localize(datetime.datetime.today()))
			i = 0
			# save each returned content block in a separate file with the filename ending ..._part_N.stix
			for i, block in enumerate(content_blocks, 1):
				collection_filename = "{}_part_{}.stix".format(collection.name, i) 
				with open(os.path.join(tmp_dir, collection_filename), 'wb') as f:
					f.write(block.content)
			if verbose:
				if i != 0:
					logging.info("Successfully downloaded collection {} into {} file(s)".format(collection.name, i))
				else:
					logging.warning("Successfully polled collection {}, but there was nothing to download for the specified timeframe".format(collection.name))
		except Exception as e:
			if verbose:
				logging.error("Could not download collection: {}. Details: {}".format(collection.name, e))
			continue
	
	return

def main():
	# retrive command line arguments
	args = parse_command_line_args()

	# ensure supplied directory exists
	if not os.path.isdir(args.output_dir):
		sys.exit("Error: Supplied output directory '{}' either doesn't exist or is not a directory".format(args.output_dir))

	# disable insecure request warnings to stdout, will still log warnings
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

	# setup logging
	log_file_path = os.path.join(args.output_dir, "threat_intel_toolkit.log")
	logging.basicConfig(filename=log_file_path, level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
	logging.info("ExtraHop Threat Intelligence Toolkit started running")

	# make temporary directory
	tmp_dir_name = "{}_{}".format(strip_non_alphanum(args.threat_collection_name), datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
	tmp_dir = os.path.join(args.output_dir, tmp_dir_name)
	os.makedirs(tmp_dir)

	# generate stix file from flat file
	if args.generate_stix:
		generate_stix_file(args.input_file, args.list_type, args.delimiter, args.list_name, args.threat_collection_name, tmp_dir, args.validate_input, args.verbose)
	# else poll stix collections from taxii server
	else:
		poll_taxii_server(args.taxii_server, args.basic_user, args.basic_pw, args.taxii_collections, args.days_to_poll, tmp_dir, args.verbose)

	# only proceed with packaging and uploading if there are files present
	if os.listdir(tmp_dir):
		# create the gzipped tar file of the temporary directory
		tgz_name = "{}.tgz".format(tmp_dir_name)
		tgz_path = os.path.join(args.output_dir, tgz_name)
		with tarfile.open(tgz_path, "w:gz") as tar:
			tar.add(tmp_dir, arcname=os.path.basename(tmp_dir))
		logging.info("Successfully created tgz file named {} in {}".format(tgz_name, args.output_dir))

		# upload the threat collection to one ECA and one or more EDAs
		if args.eca:
			# if an ECA is provided then at least one EDA is needed too to keep them in sync
			if args.edas:
				threatcollection_api_request(args.eca[0], args.eca[1], str_to_bool(args.eca[2]), args.threat_collection_name, tgz_name, tgz_path, args.verbose)
				for eda in args.edas:
					threatcollection_api_request(eda[0], eda[1], str_to_bool(eda[2]), args.threat_collection_name, tgz_name, tgz_path, args.verbose)
			else:
				logging.warning("Did not upload threat collection to ECA since no accompanying EDAs were provided")
		# if only EDAs are provided
		elif args.edas:
			for eda in args.edas:
					threatcollection_api_request(eda[0], eda[1], str_to_bool(eda[2]), args.threat_collection_name, tgz_name, tgz_path, args.verbose)
		else:
			logging.warning("Did not upload threat collection to an ExtraHop appliance since neither an ECA/EDAs nor EDAs were provided")

		# optionally delete the .tgz after upload
		if (args.eca or args.edas) and args.clean_up:
			try:
				os.remove(tgz_path)
				logging.info("Successfully cleaned up and removed the local threat collection tgz file: {}".format(tgz_name))
			except OSError as e:
				logging.error("Could not delete the local threat collection .tgz file: {}. Details: {}.".format(tgz_path, e.strerror))
	else:
		logging.warning('There were no threat intel results to process. Note: If polling a TAXII server ensure that the collection(s) contain results')

	# remove the temporary directory
	try:
		shutil.rmtree(tmp_dir)
	except OSError as e:
		logging.error("Could not delete the temporary directory: {}. Details: {}.".format(tmp_dir_name, e.strerror))

	logging.info('ExtraHop Threat Intelligence Toolkit finished running')

if __name__ == '__main__':
	main()
