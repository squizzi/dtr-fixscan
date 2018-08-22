#!/usr/bin/env python
# Find and fix corrupted DTR scanning layers and images
# Kyle Squizzato <kyle.squizzato@docker.com>

import sys
import re
import logging
import docker
import requests
import subprocess
import argparse
from logrusformatter import LogrusFormatter


global cli
cli = docker.DockerClient(base_url='unix://var/run/docker.sock')

"""
Yes or no prompting
"""
def yes_no(question):
    yes = set(['yes','y'])
    no = set(['no','n'])
    prompt = " [Yes / No] "
    while True:
        print question + '?' + prompt
        choice = raw_input().lower()
        if choice == '':
            # If no choice is given, return no
            return False
        if choice in no:
            return False
        if choice in yes:
            return True
        else:
           print "\nPlease respond with 'yes' or 'no'"

"""
Check for deletion in a reql result to ensure something was actually deleted
"""
def check_for_delete(reql_result):
    try:
        deleted_value = re.search('"deleted":[0-9]', reql_result).group(0)
    except AttributeError:
        logging.error("reql result: {0} does not contain a deleted value".format(reql_result))
        # Consider the value possibly not cleaned, but keep going
        return False
    if deleted_value.split(':')[1] == '1':
        return True
    else:
        return False

"""
Probe determine's which digests and repository namespaces are potentially
corrupted by scanning the dtr-api logs from the host where this script is ran.
It creates two new global vars for images and digests found.
"""
def probe():
    # Read the dtr-api containers logs and pull out relevant digest and image
    # information
    #logging.info("Determining which images and digests may have corrupted scan data")
    api_filter = {'name': 'dtr-api'}
    try:
        api_container = cli.containers.list(filters=api_filter)[0]
    except IndexError:
        logging.error("Unable to continue: dtr-api container not found, is DTR running correctly here?")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        logging.error("No docker socket found, was /var/run/docker.sock mounted?")
        sys.exit(1)
    logs = api_container.logs().splitlines()
    # Instantiate empty match lists
    matched_digests = []
    repo_list = []
    namespace_list = []
    for line in logs:
        if "Unable to make tag scan summary" in line:
            # If we can find the tag scan failure message in the log line pull the
            # digest from it
            try:
                digest = re.search("sha256:[A-Fa-f0-9]{64}", line).group(0)
                matched_digests.append(digest)
                image = re.search("image (?:[a-zA-Z0-9_-]+\/)?([a-zA-Z0-9_-]+)?", line).group(0)
                if len(image) > 0:
                    # If we find an image match extract the namespace and repo
                    # portion only and get rid of the extra cruft pulled by
                    # the regex limitation then form two lists to build a dict
                    # from later
                    # Ex. admin/alpine = namespace/repository
                    repo_namespace = image.split(' ')[1].split('/')
                    try:
                        namespace = repo_namespace[0]
                        repo = repo_namespace[1]
                    except IndexError as e:
                        logging.error("Unable to construct scan failure data: {0}".format(e))
                    namespace_list.append(namespace)
                    repo_list.append(repo)
            except AttributeError:
                # Skip digests or images that don't match the regex
                pass
    # Check len of lists, we only need to check either repo or namespace here
    # since there len's should be identical
    if len(repo_list + matched_digests) <= 0:
        logging.info("No corrupted scan data found, exiting")
        sys.exit(1)
    # Drop the non-unique digests and images then set back to list for iteration
    global images
    global digests
    digests = list(set(matched_digests))
    # Place image:tag list into a dict of namespace:repository
    images = dict(zip(namespace_list, repo_list))
    # Log a list of images and digests that are effected
    logging.info("Digests potentially corrupted: {0}".format(digests))
    logging.info("Repository/namespaces potentially corrupted: {0}".format(images))

"""
Clean iterate's over the digests list and images dict to perform cleanup using
appropriate ReQL commands
"""
def clean():
    # Prompt the user that we're about to begin the cleaning process which
    # will attempt to remove scanning data from rethinkdb
    logging.warn("Preparing to clean corrupted scanning data from DTR metadata, this is a potentially dangerous operation, please ensure you've performed a DTR metadata backup before continuing.")
    if not yes_no("Are you sure you wish to continue"):
        sys.exit(1)
    # Clean digests
    # Make sure the rethinkdb container is running prior to attempting to use it
    rethink_filter = {'name': 'dtr-rethinkdb'}
    try:
        api_container = cli.containers.list(filters=rethink_filter)[0]
    except IndexError:
        logging.error("Unable to continue: dtr-rethinkdb container not found, is DTR running correctly here?")
        sys.exit(1)
    logging.info("Cleaning corrupted digest scanning metadata...")
    # Iterate through the digests list and call reql commands
    for digest in digests:
        logging.debug("Cleaning digest: {0}".format(digest))
        # FIXME: This is hacky, use docker-py
        command = "r.db('dtr2').table('scanned_layers').filter({{'digest':'{0}'}}).delete()".format(digest)
        logging.debug("Issuing command: {0}".format(command))
        try:
            reql_result = subprocess.check_output("echo \"{0}\" | docker exec -i $(docker ps -lqf name=dtr-rethinkdb) rethinkcli non-interactive".format(command),
                            shell=True)
            if not check_for_delete(reql_result):
                logging.debug("digest: {0} has already been cleaned".format(digest))
        except subprocess.CalledProcessError as e:
            logging.error("Unable to clean: reql command failed: {0}".format(e))
    logging.info("Digests cleaned")
    logging.info("Cleaning corrupted repository and namespace metadata...")
    # Clean images
    # Iterate through the images dict and clean n (namespace) r (repository)
    # with relevant reql
    for n, r in images.items():
        logging.debug("Cleaning {0}/{1}".format(n, r))
        # FIXME: This is hacky, use docker-py
        command = "r.db('dtr2').table('scanned_images').filter('{{\"repository\":\"{0}\",\"namespace\":\"{1}\"}}').delete()".format(r, n)
        logging.debug("Issuing command: {0}".format(command))
        try:
            reql_result = subprocess.check_output("echo \"{0}\" | docker exec -i $(docker ps -lqf name=dtr-rethinkdb) rethinkcli non-interactive".format(command),
                            shell=True)
            if not check_for_delete(reql_result):
                logging.debug("{0}/{1} has already been cleaned".format(r, n))
        except subprocess.CalledProcessError as e:
            logging.error("Unable to clean: reql command failed: {0}".format(e))
    logging.info("Repositories and namespaces cleaned")

def main():
    # argument parsing
    parser = argparse.ArgumentParser(description='Clean corrupted scanning \
    metadata from Docker Trusted Registry 2.5.  Not intended for use on other \
    DTR versions.')
    parser.add_argument("--debug",
                        dest="debug",
                        action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()
    # basic logging that matches logrus format
    fmt_string = "%(levelname)s %(message)-20s"
    fmtr = LogrusFormatter(colorize=True, fmt=fmt_string)
    logger = logging.getLogger(name=None)
    if not args.debug:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.DEBUG)
    hdlr = logging.StreamHandler(sys.stdout)
    hdlr.setFormatter(fmtr)
    logger.addHandler(hdlr)
    # Run probe/clean functions
    probe()
    clean()
    logging.info("Complete")

"""
Main
"""
if __name__ == '__main__':
    sys.exit(main())
