#!/bin/bash

rsync -ruvz -e 'ssh -p 22223' --delete '/home/nick/Desktop/shmmy/7ο_εξάμηνο/Εργαστήριο_Λειτουργικών/oslab-ntua/exercise-2/nick' root@localhost:/root 
