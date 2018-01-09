#!/bin/bash

go build ..

./cryptogen generate --config crypto-config.yaml
rm -rf crypto-config

./cryptogen generate --config crypto-config.yaml --sm2
rm -rf crypto-config
