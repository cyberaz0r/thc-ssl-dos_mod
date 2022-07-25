#!/bin/bash
ps aux | grep thc-ssl-dos | awk '{print $2}' | xargs -I {} kill {}