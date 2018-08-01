# Fix corrupted DTR scanning
This script should only be ran on Docker Trusted Registry 2.5.4+ as a workaround
to help resolve a known issue with corrupted DTR scanning metadata.  Do not run
this script unless advised by a member of Docker Support.

## Usage

This script scan's the `dtr-api` container for API failures that have
potentially been created by corrupted DTR scanning metadata and calls relevant
ReQL (Rethink Query Language) to remove these corrupt entries from the DTR
metadata database.

**Note**: The script is not intelligent and re-running the script will re-read old
`dtr-api` entries and result in the removal of what it believes may be corrupted
metadata.

1. Perform a [backup of the DTR
   metadata](https://docs.docker.com/ee/dtr/admin/disaster-recovery/create-a-backup/#backup-dtr-metadata)

2. Find and clean corrupted scanning metadata with the `dtr-fixscan` image:

~~~
docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock squizzi/dtr-fixscan:v2.5.4+
~~~
