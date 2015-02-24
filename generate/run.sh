#!/bin/sh

socat TCP-LISTEN:3000,reuseaddr,fork,bind=localhost EXEC:"./vuln"
