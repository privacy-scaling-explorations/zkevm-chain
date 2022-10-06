#!/bin/sh

set -xe

# Requires the following env variables:
# AWS_ACCESS_KEY_ID
# AWS_SECRET_ACCESS_KEY
# AWS_DEFAULT_REGION
# AWS_INSTANCE_ID

while true; do
  status=$(aws ec2 start-instances --instance-ids "$AWS_INSTANCE_ID" | jq -r .StartingInstances[0].CurrentState.Name)
  echo "$status"
  if [[ "$status" == "running" ]]; then
    break
  fi
  sleep 3
done
