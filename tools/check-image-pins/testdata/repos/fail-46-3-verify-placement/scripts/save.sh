#!/bin/sh
# Saves the image the job built, by tag.
docker save ghcr.io/keepia/mail-postfix:dev -o image.tar
