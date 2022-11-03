#!/bin/sh

set -xe

# Requires the following env variables:
# AWS_ACCESS_KEY_ID
# AWS_SECRET_ACCESS_KEY
# AWS_DEFAULT_REGION
# AWS_INSTANCE_ID

if [ -z "$AWS_DEFAULT_REGION" ]; then
  exit 1
fi

while true; do
  status=$(aws ec2 start-instances --instance-ids "$AWS_INSTANCE_ID" | jq -r .StartingInstances[0].CurrentState.Name)
  if [ "$status" = "running" ]; then
    break
  fi
  sleep 3
done
