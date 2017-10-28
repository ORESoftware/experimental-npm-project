#!/usr/bin/env node

const cp = require('child_process');
const path = require('path');
const dirSource = path.resolve(__dirname + '/deps/*');
const dirDest = path.resolve(__dirname + '/node_modules');

cp.execSync(`rm -rf ${dirDest}`);
cp.execSync('npm install');
cp.execSync(`cp -r ${dirSource} ${dirDest}`);

