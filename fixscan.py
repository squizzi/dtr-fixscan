#!/usr/bin/env python
# Find and fix corrupted DTR scanning layers and images
# Kyle Squizzato <kyle.squizzato@docker.com>

import sys
import os
import re
import logging
import docker
import subprocess

cli = docker.DockerClient(base_url='unix://var/run/docker.sock')

# Create a simple logger
logger = logging.getLogger(name=None)
logging.basicConfig(format='[%(levelname)s] %(message)s',
                    level=logging.INFO)

# Read the dtr-api containers logs and pull out relevant digest and image
# information
logging.info("Extracting images and digests that may have corrupted scan data")
api_filter = {'name': 'dtr-api'}
try:
    api_container = cli.containers.list(filters=api_filter)[0]
except IndexError:
    logging.error("dtr-api container not found, is DTR running correctly here?")
logs = api_container.logs().splitlines()
# Instantiate empty match lists
matched_digests = []
matched_images = []
for line in logs:
    if "Unable to make tag scan summary" in line:
        # If we can find the tag scan failure message in the log line pull the
        # digest from it
        try:
            digest = re.search("sha256:[A-Fa-f0-9]{64}", line).group(0)
            matched_digests.append(digest)
            image = re.search("\"http.request.uri\":\"\/api\/v0\/repositories\/([^/]*)\/([^/]*)", line).groups(2)
            matched_images.append(image)
        except AttributeError:
            pass
# Drop the non-unique digests and images then set back to list for iteration
digests = list(set(matched_digests))
images_list = list(set(matched_images))
# Place image:tag list into a dict of namespace:repository
images = dict((x, y) for x, y in images_list)
