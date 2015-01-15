#!/bin/bash

cd ~nodeuser
mkdir samsung
cd samsung
git clone --depth=1 git@github.com:UXCAS/bedrock.git
cd bedrock/server/api
npm install
npm start &
