#!/bin/bash
docker run -itd -v /home/ubuntu/WorkerManager/workspaces/workspace0:/home/ubuntu/new_worker/workspace --name worker0 worker /bin/bash
docker run -itd -v /home/ubuntu/WorkerManager/workspaces/workspace1:/home/ubuntu/new_worker/workspace --name worker1 worker /bin/bash
docker run -itd -v /home/ubuntu/WorkerManager/workspaces/workspace2:/home/ubuntu/new_worker/workspace --name worker2 worker /bin/bash
docker run -itd -v /home/ubuntu/WorkerManager/workspaces/workspace3:/home/ubuntu/new_worker/workspace --name worker3 worker /bin/bash
docker run -itd -v /home/ubuntu/WorkerManager/workspaces/workspace4:/home/ubuntu/new_worker/workspace --name worker4 worker /bin/bash
docker run -itd -v /home/ubuntu/WorkerManager/workspaces/workspace5:/home/ubuntu/new_worker/workspace --name worker5 worker /bin/bash
docker run -itd -v /home/ubuntu/WorkerManager/workspaces/workspace6:/home/ubuntu/new_worker/workspace --name worker6 worker /bin/bash
docker run -itd -v /home/ubuntu/WorkerManager/workspaces/workspace7:/home/ubuntu/new_worker/workspace --name worker7 worker /bin/bash
